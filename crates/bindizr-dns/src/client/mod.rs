//! Outbound DNS client paths: NOTIFY fan-out and secondary SOA probing, plus
//! the UDP exchange, message-build, and secondary-resolution helpers they
//! share.

pub mod notify;
pub mod probe;

use std::{net::SocketAddr, time::Duration};

use domain::base::{MessageBuilder, Name, Rtype, iana::Opcode};
use tokio::net::{UdpSocket, lookup_host};

use crate::{
    address::{ParsedAddress, parse_address_target},
    error::XfrError,
    log_error,
};

/// Maximum size of a UDP DNS response we accept.
const UDP_RESPONSE_BUF: usize = 512;

/// Send one UDP DNS message and wait for a single response, with `timeout`
/// applied to both directions. `what` names the operation in error messages
/// (e.g. "NOTIFY").
pub(crate) async fn udp_exchange(
    server_addr: SocketAddr,
    timeout: Duration,
    request: &[u8],
    what: &str,
) -> Result<(usize, [u8; UDP_RESPONSE_BUF]), XfrError> {
    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(XfrError::IoError)?;
    socket
        .connect(server_addr)
        .await
        .map_err(XfrError::IoError)?;

    let sent = tokio::time::timeout(timeout, socket.send(request))
        .await
        .map_err(|_| XfrError::ProtocolError(format!("{} send timeout", what)))?
        .map_err(XfrError::IoError)?;
    if sent != request.len() {
        return Err(XfrError::ProtocolError(format!(
            "Incomplete {} send to {}: sent {} of {} bytes",
            what,
            server_addr,
            sent,
            request.len()
        )));
    }

    let mut response = [0u8; UDP_RESPONSE_BUF];
    let received = tokio::time::timeout(timeout, socket.recv(&mut response))
        .await
        .map_err(|_| {
            XfrError::ProtocolError(format!("{} response timeout from {}", what, server_addr))
        })?
        .map_err(XfrError::IoError)?;

    Ok((received, response))
}

/// Build a single-SOA-question DNS message with a random id, returning
/// `(query_id, wire bytes)`.
pub(crate) fn build_question(opcode: Opcode, aa: bool, qname: &Name<Vec<u8>>) -> (u16, Vec<u8>) {
    let query_id = rand::random::<u16>();

    let mut builder = MessageBuilder::new_vec();
    let header = builder.header_mut();
    header.set_id(query_id);
    header.set_opcode(opcode);
    header.set_aa(aa);

    let mut question = builder.question();
    // Composing one question into a Vec cannot fail.
    question.push((qname, Rtype::SOA)).unwrap();

    (query_id, question.finish())
}

/// Resolve the comma-separated `secondary_addrs` config value into per-entry
/// results: the original entry text plus its resolved addresses (all of them;
/// callers pick what they need) or the resolution failure. `resolve_timeout`
/// bounds each hostname lookup so a stalled system resolver fails the entry
/// instead of hanging the caller.
pub(crate) async fn resolve_secondary_entries(
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
