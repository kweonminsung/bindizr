//! Client-side SOA probing of the enabled secondaries, used to report how
//! far each has caught up with a zone.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use bindizr_core::{
    config,
    dns::{
        message::{Name, Opcode, Rtype},
        query::{build_question, extract_soa_serial},
    },
};

use crate::{model::secondary::Secondary, secondary::SecondaryService};

/// Result of probing one secondary: the serial its SOA answer carries, or
/// the reason the probe failed.
pub struct ProbeReport {
    pub address: String,
    pub result: Result<u32, String>,
}

/// Query every enabled secondary for the zone's SOA serial, in parallel.
/// No enabled secondary yields an empty list.
pub async fn probe_secondaries(zone_name: &str) -> Result<Vec<ProbeReport>, String> {
    let secondaries = SecondaryService::list_enabled()
        .await
        .map_err(|e| e.to_string())?;
    if secondaries.is_empty() {
        return Ok(Vec::new());
    }

    let mut tasks = Vec::new();
    for secondary in secondaries {
        let zone_name = zone_name.to_string();
        tasks.push((
            secondary.address.clone(),
            tokio::spawn(async move { probe_secondary(&zone_name, &secondary).await }),
        ));
    }

    let mut probes = Vec::new();
    for (address, task) in tasks {
        match task.await {
            Ok(Ok(probe)) => probes.push(probe),
            Ok(Err(e)) => return Err(e),
            Err(e) => probes.push(ProbeReport {
                address,
                result: Err(format!("probe task failed: {}", e)),
            }),
        }
    }

    Ok(probes)
}

/// Query one secondary for the zone's SOA serial: its hostname is tried at
/// each resolved address until one answers.
pub async fn probe_secondary(
    zone_name: &str,
    secondary: &Secondary,
) -> Result<ProbeReport, String> {
    let timeout = Duration::from_secs(config::bindizr_config().dns.notify.timeout_secs);
    let qname =
        Name::<Vec<u8>>::from_str(zone_name).map_err(|e| format!("Invalid zone name: {}", e))?;

    let addrs = match super::resolve_address_entry(&secondary.address, timeout).await {
        Ok(addrs) => addrs,
        Err(e) => {
            return Ok(ProbeReport {
                address: secondary.address.clone(),
                result: Err(format!("failed to resolve: {}", e)),
            });
        }
    };
    let (address, result) = probe_entry(&qname, addrs, timeout).await;
    Ok(ProbeReport { address, result })
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

    last.expect("resolve_address_entry never yields an empty Ok")
}

/// Query one secondary server for its SOA status.
async fn probe_one(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<u32, String> {
    let (query_id, query) = build_question(Opcode::QUERY, false, false, qname, Rtype::SOA);

    let (received, response) =
        super::exchange_over_udp(server_addr, timeout, &query, "SOA probe").await?;

    extract_soa_serial(query_id, qname, &response[..received])
}

#[cfg(test)]
mod tests;
