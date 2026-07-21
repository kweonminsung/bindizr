//! Client-side SOA probing of configured secondaries, used to report how far
//! each secondary has caught up with a zone.

use std::{net::SocketAddr, time::Duration};

use domain::base::{
    Name, Rtype, StaticCompressor,
    iana::{Opcode, Rcode},
    message_builder::MessageBuilder,
};
use tokio::net::{UdpSocket, lookup_host};

use super::{error::XfrError, wire};
use crate::{
    address::{ParsedAddress, parse_address_target},
    config, log_error,
};

/// Result of probing one configured secondary: the serial its SOA answer
/// carries, or the reason the probe failed.
pub struct SecondaryProbe {
    pub address: String,
    pub result: Result<u32, String>,
}

/// Query every configured secondary for the zone's SOA serial, in parallel.
/// One probe per configured entry (the first resolved address is used for
/// hostname entries). An empty `secondary_addrs` yields an empty list.
pub async fn probe_secondaries(zone_name: &str) -> Result<Vec<SecondaryProbe>, XfrError> {
    let dns_config = &config::get_bindizr_config().dns;
    let raw = dns_config.secondary_addrs.clone();
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let timeout = Duration::from_secs(dns_config.notify_timeout_secs);

    let mut zone_name_bytes = Vec::new();
    wire::encode_domain_name(zone_name, &mut zone_name_bytes)?;
    let qname = Name::from_octets(zone_name_bytes)
        .map_err(|e| XfrError::ProtocolError(format!("Invalid zone name: {}", e)))?;

    let mut probes = Vec::new();
    let mut tasks = Vec::new();
    for item in raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        let target = match parse_address_target(trimmed, 53) {
            ParsedAddress::SocketAddr(addr) => Some(addr),
            ParsedAddress::HostPort(host_port) => match lookup_host(&host_port).await {
                Ok(mut resolved) => resolved.next(),
                Err(e) => {
                    log_error!("Invalid secondary address '{}': {}", trimmed, e);
                    probes.push(SecondaryProbe {
                        address: trimmed.to_string(),
                        result: Err(format!("failed to resolve: {}", e)),
                    });
                    continue;
                }
            },
        };
        let Some(addr) = target else {
            probes.push(SecondaryProbe {
                address: trimmed.to_string(),
                result: Err("failed to resolve: no addresses".to_string()),
            });
            continue;
        };

        let qname = qname.clone();
        tasks.push((
            addr.to_string(),
            tokio::spawn(async move { probe_one(&qname, addr, timeout).await }),
        ));
    }

    for (address, task) in tasks {
        let result = task
            .await
            .unwrap_or_else(|e| Err(format!("probe task failed: {}", e)));
        probes.push(SecondaryProbe { address, result });
    }

    Ok(probes)
}

async fn probe_one(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<u32, String> {
    let (query_id, query) = build_soa_query(qname).map_err(|e| e.to_string())?;

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

    tokio::time::timeout(timeout, socket.send(&query))
        .await
        .map_err(|_| "send timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let mut response = [0u8; 512];
    let received = tokio::time::timeout(timeout, socket.recv(&mut response))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;

    extract_soa_serial(query_id, &response[..received])
}

/// Builds a standard SOA query (QR=0, RD=0) for the zone.
fn build_soa_query(qname: &Name<Vec<u8>>) -> Result<(u16, Vec<u8>), XfrError> {
    let query_id = rand::random::<u16>();
    let mut msg = MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
        .map_err(|e| XfrError::ProtocolError(format!("Failed to create message builder: {}", e)))?;

    let header = msg.header_mut();
    header.set_id(query_id);
    header.set_opcode(Opcode::QUERY);
    header.set_qr(false);
    header.set_rcode(Rcode::NOERROR);

    let mut question = msg.question();
    question
        .push((qname, Rtype::SOA))
        .map_err(|e| XfrError::ProtocolError(format!("Failed to add question: {}", e)))?;

    Ok((
        query_id,
        question.answer().finish().into_target().as_slice().to_vec(),
    ))
}

/// Validates a SOA query response and extracts the serial from the first SOA
/// record in the answer section.
fn extract_soa_serial(query_id: u16, response: &[u8]) -> Result<u32, String> {
    if response.len() < 12 {
        return Err(format!("response too short: {} bytes", response.len()));
    }

    let response_id = u16::from_be_bytes([response[0], response[1]]);
    if response_id != query_id {
        return Err(format!(
            "response ID mismatch: expected {}, got {}",
            query_id, response_id
        ));
    }

    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err("response does not have QR bit set".to_string());
    }
    if flags & 0x0200 != 0 {
        return Err("truncated response".to_string());
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("RCODE {}", rcode));
    }

    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        let name_len = wire::skip_name(response, pos).ok_or("malformed question name")?;
        pos = pos
            .checked_add(name_len + 4)
            .filter(|end| *end <= response.len())
            .ok_or("malformed question section")?;
    }

    for _ in 0..ancount {
        let name_len = wire::skip_name(response, pos).ok_or("malformed answer name")?;
        let header_pos = pos.checked_add(name_len).ok_or("malformed answer")?;
        if header_pos + 10 > response.len() {
            return Err("malformed answer header".to_string());
        }

        let rtype = u16::from_be_bytes([response[header_pos], response[header_pos + 1]]);
        let rdlen =
            u16::from_be_bytes([response[header_pos + 8], response[header_pos + 9]]) as usize;
        let rdata_start = header_pos + 10;
        let rdata_end = rdata_start
            .checked_add(rdlen)
            .filter(|end| *end <= response.len())
            .ok_or("malformed answer rdata")?;

        if rtype == Rtype::SOA.to_int() {
            let mname_len = wire::skip_name(response, rdata_start).ok_or("malformed SOA mname")?;
            let rname_pos = rdata_start
                .checked_add(mname_len)
                .ok_or("malformed SOA rdata")?;
            let rname_len = wire::skip_name(response, rname_pos).ok_or("malformed SOA rname")?;
            let serial_pos = rname_pos
                .checked_add(rname_len)
                .filter(|p| p + 4 <= rdata_end)
                .ok_or("SOA rdata too short for serial")?;
            return Ok(u32::from_be_bytes([
                response[serial_pos],
                response[serial_pos + 1],
                response[serial_pos + 2],
                response[serial_pos + 3],
            ]));
        }

        pos = rdata_end;
    }

    Err("no SOA record in answer".to_string())
}

#[cfg(test)]
mod tests;
