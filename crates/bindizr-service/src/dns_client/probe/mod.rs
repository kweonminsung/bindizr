//! Client-side SOA probing of the enabled secondaries, each answer classified
//! against the serial Bindizr serves.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use bindizr_core::{
    config,
    dns::{
        message::{Name, Opcode, Rtype},
        query::{build_question, extract_soa_serial},
    },
};

use crate::{
    model::secondary::Secondary, secondary::SecondaryService, types::SecondaryStatusResponse,
};

/// Query every enabled secondary for the zone's SOA serial in parallel and
/// classify each against `expected_serial`. No enabled secondary yields an
/// empty list.
pub async fn probe_secondaries(
    zone_name: &str,
    expected_serial: Option<u32>,
) -> Result<Vec<SecondaryStatusResponse>, String> {
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
            tokio::spawn(
                async move { probe_secondary(&zone_name, &secondary, expected_serial).await },
            ),
        ));
    }

    let mut probes = Vec::new();
    for (address, task) in tasks {
        match task.await {
            Ok(Ok(probe)) => probes.push(probe),
            Ok(Err(e)) => return Err(e),
            Err(e) => probes.push(SecondaryStatusResponse::from_probe(
                address,
                expected_serial,
                Err(format!("probe task failed: {}", e)),
            )),
        }
    }

    Ok(probes)
}

/// Query one secondary for the zone's SOA serial, trying its hostname at each
/// resolved address until one answers, and classify the answer against
/// `expected_serial`.
pub async fn probe_secondary(
    zone_name: &str,
    secondary: &Secondary,
    expected_serial: Option<u32>,
) -> Result<SecondaryStatusResponse, String> {
    let timeout = Duration::from_secs(config::bindizr_config().dns.notify.timeout_secs);
    let qname =
        Name::<Vec<u8>>::from_str(zone_name).map_err(|e| format!("Invalid zone name: {}", e))?;

    let addrs = match super::resolve_address_entry(&secondary.address, timeout).await {
        Ok(addrs) => addrs,
        Err(e) => {
            return Ok(SecondaryStatusResponse::from_probe(
                secondary.address.clone(),
                expected_serial,
                Err(format!("failed to resolve: {}", e)),
            ));
        }
    };
    Ok(probe_entry(&qname, addrs, timeout, expected_serial).await)
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

/// Probe the resolved addresses in order, classifying the first that answers
/// (on failure, the last one tried). NOTIFY and the transfer ACL act on every
/// resolved address, so probing only the first would contradict what
/// propagates — commonly an unusable IPv6 ahead of a working IPv4.
async fn probe_entry(
    qname: &Name<Vec<u8>>,
    addrs: Vec<SocketAddr>,
    timeout: Duration,
    expected_serial: Option<u32>,
) -> SecondaryStatusResponse {
    let mut last = None;
    for addr in addrs {
        match probe_one(qname, addr, timeout).await {
            Ok(serial) => {
                return SecondaryStatusResponse::from_probe(
                    addr.to_string(),
                    expected_serial,
                    Ok(serial),
                );
            }
            Err(e) => {
                last = Some(SecondaryStatusResponse::from_probe(
                    addr.to_string(),
                    expected_serial,
                    Err(e),
                ))
            }
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
