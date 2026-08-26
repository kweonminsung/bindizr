//! Client-side SOA probing of configured secondaries, used to report how far
//! each secondary has caught up with a zone.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use bindizr_core::{
    config,
    dns::{
        message::{Name, Opcode},
        query::{build_question, extract_soa_serial},
    },
};

use crate::dns::error::XfrError;

/// Result of probing one configured secondary: the serial its SOA answer
/// carries, or the reason the probe failed.
pub struct SecondaryProbe {
    pub address: String,
    pub result: Result<u32, String>,
}

/// Query every configured secondary for the zone's SOA serial, in parallel.
/// One probe per configured entry; a hostname entry is tried at each resolved
/// address until one answers. An empty `secondary_addrs` yields an empty list.
pub async fn probe_secondaries(zone_name: &str) -> Result<Vec<SecondaryProbe>, XfrError> {
    let dns_config = &config::bindizr_config().dns;
    let raw = dns_config.secondary_addrs.clone();
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let timeout = Duration::from_secs(dns_config.notify_timeout_secs);

    let qname = Name::<Vec<u8>>::from_str(zone_name)
        .map_err(|e| XfrError::ProtocolError(format!("Invalid zone name: {}", e)))?;

    let mut probes = Vec::new();
    let mut tasks = Vec::new();
    for (entry, result) in super::resolve_secondary_entries(&raw, timeout).await {
        let addrs = match result {
            Ok(addrs) => addrs,
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
            entry,
            tokio::spawn(async move { probe_entry(&qname, addrs, timeout).await }),
        ));
    }

    for (entry, task) in tasks {
        match task.await {
            Ok((address, result)) => probes.push(SecondaryProbe { address, result }),
            Err(e) => probes.push(SecondaryProbe {
                address: entry,
                result: Err(format!("probe task failed: {}", e)),
            }),
        }
    }

    Ok(probes)
}

/// Query one explicit server for the zone's SOA serial (e.g. bindizr's own
/// listener during health checks).
pub async fn probe_server(
    server_addr: SocketAddr,
    zone_name: &str,
    timeout: Duration,
) -> Result<u32, String> {
    let qname =
        Name::<Vec<u8>>::from_str(zone_name).map_err(|e| format!("invalid zone name: {}", e))?;
    probe_one(&qname, server_addr, timeout).await
}

/// Probe the resolved addresses in order, reporting the first that answers (on
/// failure, the last one tried). NOTIFY and the transfer ACL act on every
/// resolved address, so probing only the first would contradict what
/// propagates — commonly an unusable IPv6 ahead of a working IPv4.
async fn probe_entry(
    qname: &Name<Vec<u8>>,
    addrs: Vec<SocketAddr>,
    timeout: Duration,
) -> (String, Result<u32, String>) {
    let mut last = None;
    for addr in addrs {
        match probe_one(qname, addr, timeout).await {
            Ok(serial) => return (addr.to_string(), Ok(serial)),
            Err(e) => last = Some((addr.to_string(), Err(e))),
        }
    }

    last.expect("resolve_secondary_entries never yields an empty Ok")
}

async fn probe_one(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<u32, String> {
    let (query_id, query) = build_question(Opcode::QUERY, false, qname);

    let (received, response) = super::udp_exchange(server_addr, timeout, &query, "SOA probe")
        .await
        .map_err(|e| e.to_string())?;

    extract_soa_serial(query_id, &response[..received])
}

#[cfg(test)]
mod tests;
