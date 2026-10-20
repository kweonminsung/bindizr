//! Client-side AXFR: pull a whole zone from another server, the fetch half
//! of `zone import --from-server`.

use std::{net::SocketAddr, time::Duration};

use bindizr_core::{
    config::ImportConfig,
    dns::{
        dnssec::EncodeWireNameError,
        message::{Name, Rtype, encode_tcp_message},
        name::{ZoneName, decode_name_labels, to_fqdn},
        query::{
            TransferMessagePosition, TransferRecord, build_axfr_query,
            extract_tcp_keepalive_timeout, extract_transfer_records,
        },
    },
};
use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::oneshot};

use super::{ReadTcpMessageError, ResolveAddressError};

/// Why a zone could not be pulled from another server.
#[derive(Debug, Error)]
pub(crate) enum FetchZoneError {
    #[error("invalid zone name: {0}")]
    ZoneName(#[from] EncodeWireNameError),
    #[error("{server}: resolution timed out")]
    ResolutionTimedOut { server: String },
    #[error("failed to resolve {entry}: {source}")]
    Unresolved {
        entry: String,
        #[source]
        source: ResolveAddressError,
    },
    /// The last address tried, and why it failed.
    #[error("{addr}: {source}")]
    Server {
        addr: SocketAddr,
        #[source]
        source: Box<FetchZoneError>,
    },
    #[error("{addr}: transfer timed out")]
    TimedOut { addr: SocketAddr },
    #[error("no server address to transfer from")]
    NoAddress,
    #[error("connect failed: {0}")]
    Connect(#[source] std::io::Error),
    #[error("send failed: {0}")]
    Send(#[source] std::io::Error),
    #[error(transparent)]
    Encode(#[from] bindizr_core::dns::message::EncodeMessageError),
    #[error("read failed before the closing SOA: {0}")]
    Read(#[source] ReadTcpMessageError),
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ParseResponseError),
    #[error(transparent)]
    Rdata(#[from] bindizr_core::dns::record::ParseRdataError),
    #[error("transfer does not start with the zone's SOA")]
    NoOpeningSoa,
    #[error("transfer opens with the SOA of {found}, not {expected}")]
    WrongZone { found: String, expected: String },
    #[error("transfer carries a SOA that is not the opening one")]
    ForeignClosingSoa,
    #[error("transfer carries records after the closing SOA")]
    RecordsAfterClosingSoa,
    #[error("transfer exceeds {limit} records")]
    TooManyRecords { limit: usize },
    #[error("invalid owner name '{name}': {source}")]
    OwnerName {
        name: String,
        #[source]
        source: bindizr_core::dns::name::ParseNameError,
    },
}

/// One TCP connection to a primary, opened by the first transfer, reused by the
/// next ones (RFC 9103, Section 6.3.1) and reopened when the primary closed it.
#[derive(Debug)]
pub(crate) struct AxfrClient {
    /// The `host[:port]` list the operator named; port 53 by default.
    server: String,
    /// The address the first transfer connected to; later ones return to it.
    addr: Option<SocketAddr>,
    connection: Option<Connection>,
}

/// A reusable stream, with an idle timer only when the primary advertised one.
#[derive(Debug)]
enum Connection {
    Open(TcpStream),
    Idle {
        resume: oneshot::Sender<()>,
        stream: oneshot::Receiver<TcpStream>,
    },
}

impl Connection {
    /// Close at the advertised deadline even while the importer is applying the previous zone.
    fn spawn(stream: TcpStream, timeout: Duration) -> Self {
        let deadline = tokio::time::Instant::now() + timeout;
        let (resume, requested) = oneshot::channel();
        let (returned, receive) = oneshot::channel();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(deadline) => {},
                result = requested => {
                    if result.is_ok() {
                        let _ = returned.send(stream);
                    }
                }
            }
        });
        Self::Idle {
            resume,
            stream: receive,
        }
    }

    /// Recover an unexpired stream; an expired or dropped timer leaves none.
    async fn take(self) -> Option<TcpStream> {
        match self {
            Self::Open(stream) => Some(stream),
            Self::Idle { resume, stream } => {
                let _ = resume.send(());
                stream.await.ok()
            }
        }
    }
}

impl AxfrClient {
    /// Name the primary; nothing is resolved or connected until a transfer asks.
    pub(crate) fn new(server: &str) -> AxfrClient {
        AxfrClient {
            server: server.to_string(),
            addr: None,
            connection: None,
        }
    }

    /// Fetch AXFR records including delimiting SOAs (RFC 5936, Section 2.2) on
    /// the connection, opening or reopening it once; the whole has `import`'s timeout.
    pub(crate) async fn fetch_zone(
        &mut self,
        zone_name: &ZoneName,
        import: &ImportConfig,
    ) -> Result<Vec<TransferRecord>, FetchZoneError> {
        let qname = zone_name.to_wire_name()?;
        let deadline = tokio::time::Instant::now() + import.timeout();
        let transfer = async {
            let previous = match self.connection.take() {
                Some(connection) => connection.take().await,
                None => None,
            };
            let reused = previous.is_some();
            let (addr, mut stream) = match (self.addr, previous) {
                (Some(addr), Some(stream)) => (addr, stream),
                (Some(addr), None) => (
                    addr,
                    TcpStream::connect(addr)
                        .await
                        .map_err(FetchZoneError::Connect)?,
                ),
                (None, _) => connect_to_server(&self.server, import).await?,
            };
            self.addr = Some(addr);
            let result = match fetch_zone_on_stream(&mut stream, &qname, import.max_records).await {
                // Nothing came back on a reused connection: the primary let it
                // go, as RFC 7766, Section 6.2.1 allows, so start a fresh one.
                Err(FetchZoneError::Send(_) | FetchZoneError::Read(_)) if reused => {
                    stream = TcpStream::connect(addr)
                        .await
                        .map_err(FetchZoneError::Connect)?;
                    fetch_zone_on_stream(&mut stream, &qname, import.max_records).await
                }
                result => result.map_err(|source| FetchZoneError::Server {
                    addr,
                    source: Box::new(source),
                }),
            };
            result.map(|(records, timeout)| (records, timeout, stream))
        };
        match tokio::time::timeout_at(deadline, transfer).await {
            Ok(Ok((records, idle_timeout, stream))) => {
                // A zero timeout closes after the outstanding transfer completes (RFC 7828, Section 3.2.2).
                self.connection = match idle_timeout {
                    Some(timeout) if timeout.is_zero() => None,
                    Some(timeout) => Some(Connection::spawn(stream, timeout)),
                    None => Some(Connection::Open(stream)),
                };
                Ok(records)
            }
            Ok(Err(e)) => {
                // A failed transfer leaves the connection in an unknown state.
                Err(e)
            }
            Err(_) => Err(match self.addr {
                Some(addr) => FetchZoneError::TimedOut { addr },
                None => FetchZoneError::ResolutionTimedOut {
                    server: self.server.clone(),
                },
            }),
        }
    }
}

/// Resolve `server` and connect to the first of its addresses that accepts,
/// reporting the last refusal when none does.
async fn connect_to_server(
    server: &str,
    import: &ImportConfig,
) -> Result<(SocketAddr, TcpStream), FetchZoneError> {
    let entries = super::resolve_address_entries(server, import.timeout()).await;
    let mut last = None;
    for (entry, result) in entries {
        let addrs = result.map_err(|source| FetchZoneError::Unresolved { entry, source })?;
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok((addr, stream)),
                Err(e) => {
                    last = Some(FetchZoneError::Server {
                        addr,
                        source: Box::new(FetchZoneError::Connect(e)),
                    })
                }
            }
        }
    }
    Err(last.unwrap_or(FetchZoneError::NoAddress))
}

/// One AXFR on an open connection: read length-prefixed messages until the
/// closing SOA repeats the opening one.
async fn fetch_zone_on_stream(
    stream: &mut TcpStream,
    qname: &Name<Vec<u8>>,
    max_records: usize,
) -> Result<(Vec<TransferRecord>, Option<Duration>), FetchZoneError> {
    let (query_id, query) = build_axfr_query(qname);
    stream
        .write_all(&encode_tcp_message(&query)?)
        .await
        .map_err(FetchZoneError::Send)?;

    let expected_owner = to_fqdn(&qname.to_string());
    let expected_labels = owner_labels(&expected_owner)?;
    let mut records: Vec<TransferRecord> = Vec::new();
    let mut idle_timeout = None;
    loop {
        let response = super::read_tcp_message(stream)
            .await
            .map_err(FetchZoneError::Read)?;

        let position = if records.is_empty() {
            TransferMessagePosition::First
        } else {
            TransferMessagePosition::Following
        };
        let batch = extract_transfer_records(query_id, qname, position, &response)?;
        if let Some(timeout) = extract_tcp_keepalive_timeout(&response)?
            && idle_timeout != Some(Duration::ZERO)
        {
            idle_timeout = Some(timeout);
        }
        let batch_len = batch.len();
        for (index, record) in batch.into_iter().enumerate() {
            if records.is_empty() {
                if record.rtype != Rtype::SOA {
                    return Err(FetchZoneError::NoOpeningSoa);
                }
                if owner_labels(&record.name)? != expected_labels {
                    return Err(FetchZoneError::WrongZone {
                        found: record.name,
                        expected: expected_owner,
                    });
                }
            } else if record.rtype == Rtype::SOA {
                // The stream ends by repeating the opening SOA (RFC 5936, Section 2.2).
                // Compare canonical copies, preserving received case for import.
                let opening = &records[0];
                if owner_labels(&record.name)? != owner_labels(&opening.name)?
                    || record.rdata.to_canonical(Rtype::SOA)?
                        != opening.rdata.to_canonical(Rtype::SOA)?
                {
                    return Err(FetchZoneError::ForeignClosingSoa);
                }
                if index + 1 != batch_len {
                    return Err(FetchZoneError::RecordsAfterClosingSoa);
                }
                records.push(record);
                return Ok((records, idle_timeout));
            }
            records.push(record);
            if records.len() > max_records {
                return Err(FetchZoneError::TooManyRecords { limit: max_records });
            }
        }
    }
}

/// Owner names compare as labels, never as text (RFC 4343 case, escapes).
fn owner_labels(name: &str) -> Result<Vec<Vec<u8>>, FetchZoneError> {
    decode_name_labels(name)
        .map(|(labels, _)| labels)
        .map_err(|source| FetchZoneError::OwnerName {
            name: name.to_string(),
            source,
        })
}

#[cfg(test)]
mod tests;
