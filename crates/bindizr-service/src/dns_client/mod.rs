//! Outbound NOTIFY, SOA/parent-DS probes and AXFR clients with shared UDP/resolution
//! helpers; wire formats belong to core.

pub(crate) mod axfr;
pub(crate) mod ds;
pub(crate) mod notify;
pub mod probe;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bindizr_core::dns::address::{AddressTarget, DEFAULT_DNS_PORT};
use bindizr_core::dns::message::{EncodeMessageError, Keepalive, ParseQueryError, QueryMetadata};
use bindizr_core::dns::{message, query};
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};
use tokio::{net, time};

/// One byte beyond the largest supported advertisement detects truncated datagrams.
const UDP_RESPONSE_BUFFER_LEN: usize = message::EDNS_UDP_PAYLOAD_SIZE as usize + 1;

/// A failed DNS exchange; `what` identifies the operation in timeout and send errors.
#[derive(Debug, Error)]
pub enum ExchangeMessageError {
    #[error("invalid outbound DNS request: {0}")]
    InvalidRequest(#[from] ParseQueryError),
    #[error(transparent)]
    Encode(#[from] EncodeMessageError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{what} TCP timeout")]
    TcpTimedOut { what: &'static str },
    #[error("{what} send timeout")]
    SendTimedOut { what: &'static str },
    #[error("incomplete {what} send to {addr}: sent {sent} of {len} bytes")]
    IncompleteSend {
        what: &'static str,
        addr: SocketAddr,
        sent: usize,
        len: usize,
    },
    #[error("{what} response timeout from {addr}")]
    ResponseTimedOut {
        what: &'static str,
        addr: SocketAddr,
    },
}

/// Why a `host[:port]` entry named no address.
#[derive(Debug, Error)]
pub enum ResolveAddressError {
    #[error("no addresses")]
    NoAddresses,
    #[error(transparent)]
    Lookup(#[from] io::Error),
    #[error("resolution timed out after {secs} seconds")]
    TimedOut { secs: u64 },
}

/// Ask over UDP and, when the answer comes back truncated, again over TCP
/// (RFC 1035, Section 4.2.1).
pub(crate) async fn exchange_with_tcp_fallback(
    server_addr: SocketAddr,
    timeout: Duration,
    request: &[u8],
    what: &'static str,
) -> Result<Vec<u8>, ExchangeMessageError> {
    let (received, response) = exchange_over_udp(server_addr, timeout, request, what).await?;
    if !query::is_truncated(&response[..received]) {
        return Ok(response[..received].to_vec());
    }
    exchange_over_tcp(server_addr, timeout, request, what).await
}

/// Send one DNS message over TCP, length-prefixed (RFC 1035, Section
/// 4.2.2), and read the single response; `timeout` covers the whole exchange.
pub(crate) async fn exchange_over_tcp(
    server_addr: SocketAddr,
    timeout: Duration,
    request: &[u8],
    what: &'static str,
) -> Result<Vec<u8>, ExchangeMessageError> {
    use tokio::io::AsyncWriteExt;

    let frame = message::encode_tcp_message(request)?;

    let exchange = async {
        let mut stream = TcpStream::connect(server_addr).await?;
        stream.write_all(&frame).await?;
        Ok(read_tcp_message(&mut stream).await?)
    };

    time::timeout(timeout, exchange)
        .await
        .map_err(|_| ExchangeMessageError::TcpTimedOut { what })?
}

/// Read one length-prefixed DNS message (RFC 1035, Section 4.2.2).
pub(crate) async fn read_tcp_message(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut prefix = [0; 2];
    stream.read_exact(&mut prefix).await?;
    let mut message = vec![0; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

/// Exchange one UDP DNS message, timing out each direction and naming
/// the operation with `what` in errors.
pub(crate) async fn exchange_over_udp(
    server_addr: SocketAddr,
    timeout: Duration,
    request: &[u8],
    what: &'static str,
) -> Result<(usize, [u8; UDP_RESPONSE_BUFFER_LEN]), ExchangeMessageError> {
    let limit = QueryMetadata::parse(request, Keepalive::None)?.response_limit();
    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(server_addr).await?;

    let sent = time::timeout(timeout, socket.send(request))
        .await
        .map_err(|_| ExchangeMessageError::SendTimedOut { what })??;

    if sent != request.len() {
        return Err(ExchangeMessageError::IncompleteSend {
            what,
            addr: server_addr,
            sent,
            len: request.len(),
        });
    }

    let mut response = [0; UDP_RESPONSE_BUFFER_LEN];

    let receive = async {
        loop {
            let received = socket.recv(&mut response[..=limit.max_len()]).await?;

            // Ignore unmatched datagrams without extending the exchange's deadline.
            if limit.validate_len(received).is_ok()
                && query::matches_response_to_request(request, &response[..received])
            {
                return Ok::<_, io::Error>(received);
            }
        }
    };
    let received = time::timeout(timeout, receive).await.map_err(|_| {
        ExchangeMessageError::ResponseTimedOut {
            what,
            addr: server_addr,
        }
    })??;

    Ok((received, response))
}

/// Resolve a comma-separated `host[:port]` list into per-entry results: the
/// entry text plus every resolved address, or the failure.
pub(crate) async fn resolve_address_entries(
    raw: &str,
    timeout: Duration,
) -> Vec<(String, Result<Vec<SocketAddr>, ResolveAddressError>)> {
    let mut entries = Vec::new();

    for entry in raw.split(',') {
        let trimmed = entry.trim();

        if trimmed.is_empty() {
            continue;
        }

        let target = AddressTarget::parse(trimmed, DEFAULT_DNS_PORT);

        let result = resolve_address_entry(&target, timeout).await;
        entries.push((trimmed.to_string(), result));
    }

    entries
}

/// Resolve `host[:port]` (default 53), bounded by `timeout`.
pub async fn resolve_address_entry(
    target: &AddressTarget,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, ResolveAddressError> {
    match target {
        AddressTarget::Socket(addr) => Ok(vec![*addr]),
        AddressTarget::HostPort(host_port) => {
            match time::timeout(timeout, net::lookup_host(host_port)).await {
                Ok(Ok(resolved)) => {
                    let addrs: Vec<SocketAddr> = resolved.collect();
                    if addrs.is_empty() {
                        Err(ResolveAddressError::NoAddresses)
                    } else {
                        Ok(addrs)
                    }
                }
                Ok(Err(error)) => Err(ResolveAddressError::Lookup(error)),
                Err(_) => Err(ResolveAddressError::TimedOut {
                    secs: timeout.as_secs(),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bindizr_core::dns::message::{Opcode, OptRcode, ParsedQuery, Rtype};
    use bindizr_core::dns::name::WireName;

    use super::*;

    /// Verify that a UDP exchange ignores over-advertisement replies without resetting the
    /// deadline or sending again.
    #[tokio::test]
    async fn udp_exchange_ignores_oversized_matching_responses() {
        use std::str::FromStr;

        for (advertised, limit) in [(None, 512), (Some(1232), 1232)] {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let (_, query) = query::build_question(
                Opcode::QUERY,
                false,
                false,
                &WireName::from_str("example.com").unwrap(),
                Rtype::SOA,
                advertised,
            );
            let query = query.finish();

            let mut exchange = tokio::spawn(async move {
                exchange_over_udp(addr, Duration::from_secs(1), &query, "test").await
            });

            let mut buffer = [0; 1232];

            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = ParsedQuery::parse(&buffer[..len], Keepalive::None).unwrap();
            let valid = query
                .build_signed_error_response(OptRcode::NOERROR, None, None)
                .unwrap();

            for size in [limit + 1, 4096] {
                let mut oversized = valid.clone();
                oversized.resize(size, 0);

                socket.send_to(&oversized, peer).await.unwrap();

                assert!(
                    time::timeout(Duration::from_millis(20), &mut exchange)
                        .await
                        .is_err()
                );
            }

            socket.send_to(&valid, peer).await.unwrap();
            let (len, response) = exchange.await.unwrap().unwrap();

            assert_eq!(&response[..len], valid);
        }
    }
}
