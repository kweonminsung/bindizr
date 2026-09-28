//! Outbound DNS client paths — NOTIFY fan-out, SOA and parent-DS probing,
//! and inbound zone transfers — plus the UDP exchange and address-resolution
//! helpers they share. The wire format itself stays in core.

pub(crate) mod axfr;
pub(crate) mod ds;
pub mod notify;
pub mod probe;

use std::{net::SocketAddr, time::Duration};

use bindizr_core::dns::{
    address::{AddressTarget, DEFAULT_DNS_PORT},
    message::encode_tcp_message,
    query::is_truncated,
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
};

/// Why one exchange with a server produced no response. `what` names the
/// operation (`"NOTIFY"`, `"SOA probe"`) so the message stands on its own.
#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error(transparent)]
    Encode(#[from] bindizr_core::dns::message::EncodeMessageError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{what} TCP timeout")]
    TcpTimedOut { what: &'static str },
    #[error("{what} send timeout")]
    SendTimedOut { what: &'static str },
    #[error("Incomplete {what} send to {server}: sent {sent} of {len} bytes")]
    IncompleteSend {
        what: &'static str,
        server: SocketAddr,
        sent: usize,
        len: usize,
    },
    #[error("{what} response timeout from {server}")]
    ResponseTimedOut {
        what: &'static str,
        server: SocketAddr,
    },
}

/// Why a `host[:port]` entry named no address.
#[derive(Debug, Error)]
pub enum ResolveAddressError {
    #[error("no addresses")]
    NoAddresses,
    #[error(transparent)]
    Lookup(#[from] std::io::Error),
    #[error("resolution timed out after {secs} seconds")]
    TimedOut { secs: u64 },
}

/// Maximum size of a UDP DNS response we accept: room for the
/// `EDNS_UDP_PAYLOAD_SIZE` the parent DS questions advertise.
const UDP_RESPONSE_BUF: usize = 4096;

/// Ask over UDP and, when the answer comes back truncated, again over TCP
/// (RFC 1035, Section 4.2.1).
pub(crate) async fn exchange_with_tcp_fallback(
    server_addr: SocketAddr,
    timeout: Duration,
    request: &[u8],
    what: &'static str,
) -> Result<Vec<u8>, ExchangeError> {
    let (received, response) = exchange_over_udp(server_addr, timeout, request, what).await?;
    if !is_truncated(&response[..received]) {
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
) -> Result<Vec<u8>, ExchangeError> {
    let frame = encode_tcp_message(request)?;
    let exchange = async {
        let mut stream = TcpStream::connect(server_addr).await?;
        stream.write_all(&frame).await?;
        Ok(read_tcp_message(&mut stream).await?)
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| ExchangeError::TcpTimedOut { what })?
}

/// Read one length-prefixed DNS message (RFC 1035, Section 4.2.2).
pub(crate) async fn read_tcp_message(stream: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

/// Send one UDP DNS message and wait for a single response, with `timeout`
/// applied to both directions. `what` names the operation in error messages
/// (e.g. "NOTIFY").
pub(crate) async fn exchange_over_udp(
    server_addr: SocketAddr,
    timeout: Duration,
    request: &[u8],
    what: &'static str,
) -> Result<(usize, [u8; UDP_RESPONSE_BUF]), ExchangeError> {
    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(server_addr).await?;

    let sent = tokio::time::timeout(timeout, socket.send(request))
        .await
        .map_err(|_| ExchangeError::SendTimedOut { what })??;
    if sent != request.len() {
        return Err(ExchangeError::IncompleteSend {
            what,
            server: server_addr,
            sent,
            len: request.len(),
        });
    }

    let mut response = [0u8; UDP_RESPONSE_BUF];
    let received = tokio::time::timeout(timeout, socket.recv(&mut response))
        .await
        .map_err(|_| ExchangeError::ResponseTimedOut {
            what,
            server: server_addr,
        })??;

    Ok((received, response))
}

/// Resolve a comma-separated `host[:port]` list into per-entry results: the
/// entry text plus every resolved address, or the failure.
pub(crate) async fn resolve_address_entries(
    raw: &str,
    resolve_timeout: Duration,
) -> Vec<(String, Result<Vec<SocketAddr>, ResolveAddressError>)> {
    let mut entries = Vec::new();

    for item in raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let result = resolve_address_entry(trimmed, resolve_timeout).await;
        entries.push((trimmed.to_string(), result));
    }

    entries
}

/// Resolve one `host[:port]` entry (port 53 default) into every address it
/// names. `resolve_timeout` bounds the lookup so a stalled system resolver
/// fails the entry instead of hanging the caller.
pub async fn resolve_address_entry(
    entry: &str,
    resolve_timeout: Duration,
) -> Result<Vec<SocketAddr>, ResolveAddressError> {
    match AddressTarget::parse(entry, DEFAULT_DNS_PORT) {
        AddressTarget::Socket(addr) => Ok(vec![addr]),
        AddressTarget::HostPort(host_port) => {
            match tokio::time::timeout(resolve_timeout, lookup_host(&host_port)).await {
                Ok(Ok(resolved)) => {
                    let addrs: Vec<SocketAddr> = resolved.collect();
                    if addrs.is_empty() {
                        Err(ResolveAddressError::NoAddresses)
                    } else {
                        Ok(addrs)
                    }
                }
                Ok(Err(e)) => {
                    log::error!("Invalid server address '{}': {}", entry, e);
                    Err(ResolveAddressError::Lookup(e))
                }
                Err(_) => {
                    log::error!(
                        "Resolving server address '{}' timed out after {} seconds",
                        entry,
                        resolve_timeout.as_secs()
                    );
                    Err(ResolveAddressError::TimedOut {
                        secs: resolve_timeout.as_secs(),
                    })
                }
            }
        }
    }
}
