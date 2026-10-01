//! Client-side AXFR: pull a whole zone from another server, the fetch half
//! of `zone import --from-server`.

use std::{net::SocketAddr, time::Duration};

use bindizr_core::dns::{
    dnssec::WireNameError,
    message::{Name, Opcode, Rtype, encode_tcp_message},
    name::{ZoneName, decode_name_labels, to_fqdn},
    query::{TransferMessagePosition, TransferRecord, build_question, extract_transfer_records},
};
use thiserror::Error;
use tokio::io::AsyncWriteExt;

use super::{ReadTcpMessageError, ResolveAddressError};

/// Why a zone could not be pulled from another server.
#[derive(Debug, Error)]
pub(crate) enum TransferZoneError {
    #[error("invalid zone name: {0}")]
    ZoneName(#[from] WireNameError),
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
        source: Box<TransferZoneError>,
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
    #[error("transfer exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ReadResponseError),
    #[error("transfer does not start with the zone's SOA")]
    NoOpeningSoa,
    #[error("transfer opens with the SOA of {found}, not {expected}")]
    WrongZone { found: String, expected: String },
    #[error("transfer carries a SOA that is not the opening one")]
    ForeignClosingSoa,
    #[error("transfer exceeds {limit} records")]
    TooManyRecords { limit: usize },
    #[error("invalid owner name '{name}': {source}")]
    OwnerName {
        name: String,
        #[source]
        source: bindizr_core::dns::name::ParseNameError,
    },
}

/// Transfer the zone from `server` and render it as zone-file text ready
/// for the import parser.
pub(crate) async fn fetch_zone_file(
    server: &str,
    zone_name: &ZoneName,
) -> Result<String, TransferZoneError> {
    let records = transfer_zone(server, zone_name).await?;
    Ok(render_zone_file(&records))
}

/// Bounds on one inbound transfer, guarding against a runaway server.
const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSFER_RECORDS: usize = 200_000;
/// Whole-transfer deadline: resolution and every address attempt share it.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

/// Transfer the zone from `server` (`host[:port]`, port 53 default) and
/// return its records, the delimiting SOAs included (RFC 5936, Section 2.2).
async fn transfer_zone(
    server: &str,
    zone_name: &ZoneName,
) -> Result<Vec<TransferRecord>, TransferZoneError> {
    let qname = zone_name.to_wire_name()?;

    let deadline = tokio::time::Instant::now() + TRANSFER_TIMEOUT;
    let entries = tokio::time::timeout_at(
        deadline,
        super::resolve_address_entries(server, TRANSFER_TIMEOUT),
    )
    .await
    .map_err(|_| TransferZoneError::ResolutionTimedOut {
        server: server.to_string(),
    })?;
    let mut last = None;
    for (entry, result) in entries {
        let addrs = result.map_err(|source| TransferZoneError::Unresolved { entry, source })?;
        for addr in addrs {
            match tokio::time::timeout_at(deadline, transfer_from(addr, &qname)).await {
                Ok(Ok(records)) => return Ok(records),
                Ok(Err(e)) => {
                    last = Some(TransferZoneError::Server {
                        addr,
                        source: Box::new(e),
                    })
                }
                // The deadline is absolute; later attempts would time out too.
                Err(_) => return Err(TransferZoneError::TimedOut { addr }),
            }
        }
    }
    Err(last.unwrap_or(TransferZoneError::NoAddress))
}

/// One AXFR over TCP: read length-prefixed response messages until the
/// closing SOA repeats the opening one.
async fn transfer_from(
    addr: SocketAddr,
    qname: &Name<Vec<u8>>,
) -> Result<Vec<TransferRecord>, TransferZoneError> {
    let (query_id, query) = build_question(Opcode::QUERY, false, false, qname, Rtype::AXFR);
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(TransferZoneError::Connect)?;
    stream
        .write_all(&encode_tcp_message(&query)?)
        .await
        .map_err(TransferZoneError::Send)?;

    let expected_owner = to_fqdn(&qname.to_string());
    let expected_labels = owner_labels(&expected_owner)?;
    let mut records: Vec<TransferRecord> = Vec::new();
    let mut total_bytes = 0usize;
    loop {
        let response = super::read_tcp_message(&mut stream)
            .await
            .map_err(TransferZoneError::Read)?;
        total_bytes += response.len();
        if total_bytes > MAX_TRANSFER_BYTES {
            return Err(TransferZoneError::TooLarge {
                limit: MAX_TRANSFER_BYTES,
            });
        }

        let position = if records.is_empty() {
            TransferMessagePosition::First
        } else {
            TransferMessagePosition::Following
        };
        let batch = extract_transfer_records(query_id, qname, position, &response)?;
        for record in batch {
            if records.is_empty() {
                if record.rtype != Rtype::SOA {
                    return Err(TransferZoneError::NoOpeningSoa);
                }
                if owner_labels(&record.name)? != expected_labels {
                    return Err(TransferZoneError::WrongZone {
                        found: record.name,
                        expected: expected_owner,
                    });
                }
            } else if record.rtype == Rtype::SOA {
                // The stream ends by repeating the opening SOA (RFC 5936, Section 2.2).
                let opening = &records[0];
                if owner_labels(&record.name)? != owner_labels(&opening.name)?
                    || record.rdata != opening.rdata
                {
                    return Err(TransferZoneError::ForeignClosingSoa);
                }
                records.push(record);
                return Ok(records);
            }
            records.push(record);
            if records.len() > MAX_TRANSFER_RECORDS {
                return Err(TransferZoneError::TooManyRecords {
                    limit: MAX_TRANSFER_RECORDS,
                });
            }
        }
    }
}

/// Owner names compare as labels, never as text (RFC 4343 case, escapes).
fn owner_labels(name: &str) -> Result<Vec<String>, TransferZoneError> {
    decode_name_labels(name)
        .map(|(labels, _)| labels)
        .map_err(|source| TransferZoneError::OwnerName {
            name: name.to_string(),
            source,
        })
}

/// Render transferred records as zone-file lines: the zone's SOA once, no
/// DNSSEC-derived rows (bindizr signs with its own keys), and every other
/// type as it arrived, for the parser to accept or report.
fn render_zone_file(records: &[TransferRecord]) -> String {
    let mut lines = String::new();
    let mut soa_rendered = false;
    for record in records {
        if matches!(
            record.rtype,
            Rtype::RRSIG
                | Rtype::NSEC
                | Rtype::NSEC3
                | Rtype::NSEC3PARAM
                | Rtype::DNSKEY
                | Rtype::CDS
                | Rtype::CDNSKEY
        ) {
            continue;
        }
        // The opening delimiter is what `--create` builds the zone from; the
        // closing repeat would read as a zone carrying two.
        if record.rtype == Rtype::SOA {
            if soa_rendered {
                continue;
            }
            soa_rendered = true;
        }
        // A type bindizr does not store is rendered anyway: the parser
        // reports it, so `--skip-unsupported` can pass over it.
        lines.push_str(&format!(
            "{} {} IN {} {}\n",
            record.name, record.ttl, record.rtype, record.rdata
        ));
    }
    lines
}

#[cfg(test)]
mod tests;
