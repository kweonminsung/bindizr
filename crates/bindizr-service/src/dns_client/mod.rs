//! Outbound DNS client paths — NOTIFY fan-out, SOA and parent-DS probing,
//! and inbound zone transfers — plus the UDP exchange and address-resolution
//! helpers they share. The wire format itself stays in core.

pub(crate) mod axfr;
pub mod ds;
pub mod notify;
pub mod probe;

use std::{net::SocketAddr, time::Duration};

use bindizr_core::{
    dns::{
        address::{ParsedAddress, parse_address_target},
        message::encode_tcp_message,
        query::is_truncated,
    },
    log_error,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
};

/// Maximum size of a UDP DNS response we accept: room for the
/// `EDNS_UDP_PAYLOAD_SIZE` the DS and NS questions advertise.
const UDP_RESPONSE_BUF: usize = 4096;

/// Ask over UDP and, when the answer comes back truncated, again over TCP
/// (RFC 1035, Section 4.2.1).
pub(crate) async fn exchange_with_tcp_fallback(
    server_addr: SocketAddr,
    timeout: Duration,
    request: &[u8],
    what: &str,
) -> Result<Vec<u8>, String> {
    let (received, response) = udp_exchange(server_addr, timeout, request, what).await?;
    if !is_truncated(&response[..received]) {
        return Ok(response[..received].to_vec());
    }
    tcp_exchange(server_addr, timeout, request, what).await
}

/// Send one DNS message over TCP, length-prefixed (RFC 1035, Section
/// 4.2.2), and read the single response; `timeout` covers the whole exchange.
pub(crate) async fn tcp_exchange(
    server_addr: SocketAddr,
    timeout: Duration,
    request: &[u8],
    what: &str,
) -> Result<Vec<u8>, String> {
    let frame = encode_tcp_message(request)?;
    let exchange = async {
        let mut stream = TcpStream::connect(server_addr)
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(&frame).await.map_err(|e| e.to_string())?;
        read_tcp_message(&mut stream).await
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| format!("{} TCP timeout", what))?
}

/// Read one length-prefixed DNS message (RFC 1035, Section 4.2.2).
pub(crate) async fn read_tcp_message(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|e| e.to_string())?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream
        .read_exact(&mut message)
        .await
        .map_err(|e| e.to_string())?;
    Ok(message)
}

/// Send one UDP DNS message and wait for a single response, with `timeout`
/// applied to both directions. `what` names the operation in error messages
/// (e.g. "NOTIFY").
pub(crate) async fn udp_exchange(
    server_addr: SocketAddr,
    timeout: Duration,
    request: &[u8],
    what: &str,
) -> Result<(usize, [u8; UDP_RESPONSE_BUF]), String> {
    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| e.to_string())?;
    socket
        .connect(server_addr)
        .await
        .map_err(|e| e.to_string())?;

    let sent = tokio::time::timeout(timeout, socket.send(request))
        .await
        .map_err(|_| format!("{} send timeout", what))?
        .map_err(|e| e.to_string())?;
    if sent != request.len() {
        return Err(format!(
            "Incomplete {} send to {}: sent {} of {} bytes",
            what,
            server_addr,
            sent,
            request.len()
        ));
    }

    let mut response = [0u8; UDP_RESPONSE_BUF];
    let received = tokio::time::timeout(timeout, socket.recv(&mut response))
        .await
        .map_err(|_| format!("{} response timeout from {}", what, server_addr))?
        .map_err(|e| e.to_string())?;

    Ok((received, response))
}

/// Resolve a comma-separated `host[:port]` list into per-entry results: the
/// entry text plus every resolved address, or the failure. `resolve_timeout`
/// bounds each lookup so a stalled system resolver fails the entry instead
/// of hanging the caller.
pub(crate) async fn resolve_address_entries(
    raw: &str,
    resolve_timeout: Duration,
) -> Vec<(String, Result<Vec<SocketAddr>, String>)> {
    let mut entries = Vec::new();

    for item in raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        let result = match parse_address_target(trimmed, 53) {
            ParsedAddress::SocketAddr(addr) => Ok(vec![addr]),
            ParsedAddress::HostPort(host_port) => {
                match tokio::time::timeout(resolve_timeout, lookup_host(&host_port)).await {
                    Ok(Ok(resolved)) => {
                        let addrs: Vec<SocketAddr> = resolved.collect();
                        if addrs.is_empty() {
                            Err("no addresses".to_string())
                        } else {
                            Ok(addrs)
                        }
                    }
                    Ok(Err(e)) => {
                        log_error!("Invalid server address '{}': {}", trimmed, e);
                        Err(e.to_string())
                    }
                    Err(_) => {
                        log_error!(
                            "Resolving server address '{}' timed out after {} seconds",
                            trimmed,
                            resolve_timeout.as_secs()
                        );
                        Err(format!(
                            "resolution timed out after {} seconds",
                            resolve_timeout.as_secs()
                        ))
                    }
                }
            }
        };
        entries.push((trimmed.to_string(), result));
    }

    entries
}
