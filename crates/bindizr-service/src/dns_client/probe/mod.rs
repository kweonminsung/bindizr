//! Client-side SOA probing of the enabled secondaries, each answer classified
//! against the serial Bindizr serves.

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use bindizr_core::dns::{
    Serial,
    message::{Name, Opcode, Rtype},
    name::ZoneName,
    query::{build_question, extract_soa_serial},
};
use thiserror::Error;

use super::{ExchangeError, ResolveAddressError};
use crate::{
    Context,
    error::ServiceError,
    model::secondary::Secondary,
    secondary, transfer,
    types::{SecondaryStatusResponse, TransferResponse},
};

/// Why a secondary's serial could not be read.
#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("invalid zone name: {0}")]
    ZoneName(#[source] bindizr_core::dns::LibraryError),
    #[error("failed to resolve: {0}")]
    Resolve(#[source] ResolveAddressError),
    #[error(transparent)]
    Exchange(#[from] ExchangeError),
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ReadResponseError),
    #[error("probe task failed: {0}")]
    TaskFailed(#[source] tokio::task::JoinError),
}

/// A probe that failed before any secondary answered is the server's fault:
/// the zone name is a stored row, the task a runtime.
impl From<ProbeError> for ServiceError {
    /// Report the probe failure as an internal error, keeping it as source.
    fn from(err: ProbeError) -> Self {
        ServiceError::Internal {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

/// Query every enabled secondary for the zone's SOA serial in parallel and
/// classify each against `expected_serial`. No enabled secondary yields an
/// empty list.
pub async fn probe_secondaries(
    cx: &Context,
    zone_name: &ZoneName,
    expected_serial: Option<Serial>,
) -> Result<Vec<SecondaryStatusResponse>, ServiceError> {
    let secondaries = secondary::list_enabled(cx).await?;
    if secondaries.is_empty() {
        return Ok(Vec::new());
    }

    let timeout = Duration::from_secs(cx.config().dns.notify.timeout_secs);

    // The network half owns its inputs, so each probe runs on a task of its
    // own; the transfer lookup that needs the context follows on this one.
    let mut tasks = Vec::new();
    for secondary in secondaries {
        let zone_name = zone_name.clone();
        tasks.push((
            secondary.address.clone(),
            tokio::spawn(async move {
                probe_addresses(&zone_name, &secondary, timeout, expected_serial).await
            }),
        ));
    }

    let mut probes = Vec::new();
    for (address, task) in tasks {
        match task.await {
            Ok(Ok((probe, clients))) => {
                probes.push(with_last_transfer(cx, zone_name, probe, &clients).await)
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(e) => probes.push(SecondaryStatusResponse::from_probe(
                address,
                expected_serial,
                Err(ProbeError::TaskFailed(e)),
            )),
        }
    }

    Ok(probes)
}

/// Query one secondary for the zone's SOA serial, trying its hostname at each
/// resolved address until one answers, and classify the answer against
/// `expected_serial`.
pub async fn probe_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
    expected_serial: Option<Serial>,
) -> Result<SecondaryStatusResponse, ServiceError> {
    let timeout = Duration::from_secs(cx.config().dns.notify.timeout_secs);
    let (probe, clients) = probe_addresses(zone_name, secondary, timeout, expected_serial).await?;
    Ok(with_last_transfer(cx, zone_name, probe, &clients).await)
}

/// The network half of a probe: resolve the secondary and query its
/// addresses. Owns nothing of the daemon's state, so it can run on a task of
/// its own; the addresses come back because they key the transfer rows.
async fn probe_addresses(
    zone_name: &ZoneName,
    secondary: &Secondary,
    timeout: Duration,
    expected_serial: Option<Serial>,
) -> Result<(SecondaryStatusResponse, Vec<IpAddr>), ProbeError> {
    let qname = Name::<Vec<u8>>::from_str(zone_name.as_str())
        .map_err(|e| ProbeError::ZoneName(Box::new(e)))?;

    let addrs = match super::resolve_address_entry(&secondary.address, timeout).await {
        Ok(addrs) => addrs,
        Err(e) => {
            return Ok((
                SecondaryStatusResponse::from_probe(
                    secondary.address.clone(),
                    expected_serial,
                    Err(ProbeError::Resolve(e)),
                ),
                Vec::new(),
            ));
        }
    };
    Ok(probe_entry(&qname, addrs, timeout, expected_serial).await)
}

/// Attach what Bindizr last sent the secondary for the zone, beside what it
/// serves now; a secondary that did not resolve keys no transfer row.
async fn with_last_transfer(
    cx: &Context,
    zone_name: &ZoneName,
    mut probe: SecondaryStatusResponse,
    clients: &[IpAddr],
) -> SecondaryStatusResponse {
    if clients.is_empty() {
        return probe;
    }
    probe.last_transfer =
        match transfer::find_by_clients_and_zone_name(cx, clients, zone_name).await {
            Ok(transfer) => transfer.as_ref().map(TransferResponse::from),
            Err(e) => {
                log::warn!("Failed to read the transfers of {}: {}", zone_name, e);
                None
            }
        };
    probe
}

/// Query one explicit server for the zone's SOA serial (e.g. bindizr's own
/// listener during health checks).
pub async fn probe_server(
    server_addr: SocketAddr,
    zone_name: &ZoneName,
    timeout: Duration,
) -> Result<Serial, ProbeError> {
    let qname = Name::<Vec<u8>>::from_str(zone_name.as_str())
        .map_err(|e| ProbeError::ZoneName(Box::new(e)))?;
    probe_one(&qname, server_addr, timeout).await
}

/// Probe the resolved addresses in order, classifying the first that answers
/// (on failure, the last one tried), and hand back the addresses tried.
/// NOTIFY and the transfer ACL act on every resolved address, so probing only
/// the first would contradict what propagates — commonly an unusable IPv6
/// ahead of a working IPv4.
async fn probe_entry(
    qname: &Name<Vec<u8>>,
    addrs: Vec<SocketAddr>,
    timeout: Duration,
    expected_serial: Option<Serial>,
) -> (SecondaryStatusResponse, Vec<IpAddr>) {
    let clients: Vec<IpAddr> = addrs.iter().map(|addr| addr.ip()).collect();
    let mut last = None;
    for addr in addrs {
        match probe_one(qname, addr, timeout).await {
            Ok(serial) => {
                last = Some(SecondaryStatusResponse::from_probe(
                    addr.to_string(),
                    expected_serial,
                    Ok(serial),
                ));
                break;
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

    let probe = last.expect("resolve_address_entry never yields an empty Ok");
    (probe, clients)
}

/// Query one secondary server for its SOA status.
async fn probe_one(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<Serial, ProbeError> {
    let (query_id, query) = build_question(Opcode::QUERY, false, false, qname, Rtype::SOA);
    let (received, response) =
        super::exchange_over_udp(server_addr, timeout, &query, "SOA probe").await?;
    Ok(Serial::from(extract_soa_serial(
        query_id,
        qname,
        &response[..received],
    )?))
}

#[cfg(test)]
mod tests;
