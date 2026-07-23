//! Client-side SOA probing of configured secondaries, used to report how far
//! each secondary has caught up with a zone.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use domain::{
    base::{
        Message, Name,
        iana::{Opcode, Rcode},
    },
    rdata::Soa,
};

use crate::{config, error::XfrError};

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

    let qname = Name::<Vec<u8>>::from_str(zone_name)
        .map_err(|e| XfrError::ProtocolError(format!("Invalid zone name: {}", e)))?;

    let mut probes = Vec::new();
    let mut tasks = Vec::new();
    for (entry, result) in super::resolve_secondary_entries(&raw).await {
        let addr = match result.map(|addrs| addrs.into_iter().next()) {
            Ok(Some(addr)) => addr,
            Ok(None) => unreachable!("resolve_secondary_entries never yields an empty Ok"),
            Err(e) => {
                probes.push(SecondaryProbe {
                    address: entry,
                    result: Err(format!("failed to resolve: {}", e)),
                });
                continue;
            }
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
    let (query_id, query) =
        super::build_question(Opcode::QUERY, false, qname).map_err(|e| e.to_string())?;

    let (received, response) = super::udp_exchange(server_addr, timeout, &query, "SOA probe")
        .await
        .map_err(|e| e.to_string())?;

    extract_soa_serial(query_id, &response[..received])
}

/// Validates a SOA query response and extracts the serial from the first SOA
/// record in the answer section.
fn extract_soa_serial(query_id: u16, response: &[u8]) -> Result<u32, String> {
    let message =
        Message::from_octets(response).map_err(|e| format!("malformed response: {}", e))?;

    let header = message.header();
    if header.id() != query_id {
        return Err(format!(
            "response ID mismatch: expected {}, got {}",
            query_id,
            header.id()
        ));
    }
    if !header.qr() {
        return Err("response does not have QR bit set".to_string());
    }
    if header.tc() {
        return Err("truncated response".to_string());
    }
    if header.rcode() != Rcode::NOERROR {
        return Err(format!("RCODE {}", header.rcode().to_int()));
    }

    let answer = message
        .answer()
        .map_err(|e| format!("malformed answer section: {}", e))?;
    answer
        .limit_to::<Soa<_>>()
        .find_map(|record| record.ok())
        .map(|record| record.data().serial().into_int())
        .ok_or_else(|| "no SOA record in answer".to_string())
}

#[cfg(test)]
mod tests;
