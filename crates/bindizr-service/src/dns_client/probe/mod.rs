//! SOA probes for server diagnostics and secondary serial comparisons.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use bindizr_core::dns::{
    Serial,
    dnssec::EncodeWireNameError,
    message::{Name, Opcode, Rtype},
    name::ZoneName,
    query::{build_question, extract_soa_serial},
};
use thiserror::Error;

use super::{ExchangeMessageError, ResolveAddressError};
use crate::{
    Context,
    error::ServiceError,
    model::secondary::Secondary,
    secondary, transfer,
    types::{SecondaryStatus, SecondaryStatusResponse, TransferResponse},
};

/// Why a server's SOA serial could not be read.
#[derive(Debug, Error)]
pub enum ProbeSoaError {
    #[error("invalid zone name: {0}")]
    ZoneName(#[from] EncodeWireNameError),
    #[error("failed to resolve: {0}")]
    Resolve(#[source] ResolveAddressError),
    #[error(transparent)]
    Exchange(#[from] ExchangeMessageError),
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ParseResponseError),
    #[error("probe task failed: {0}")]
    TaskFailed(#[source] tokio::task::JoinError),
}

/// A probe that failed before any secondary answered is the server's fault:
/// the zone name is a stored row, the task a runtime.
impl From<ProbeSoaError> for ServiceError {
    /// Report the probe failure as an internal error, keeping it as source.
    fn from(err: ProbeSoaError) -> Self {
        ServiceError::Internal {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

/// Compare a probed SOA serial with the served serial; errors are `unreachable`,
/// and answers without comparable serials are `reachable`.
fn build_secondary_status(
    address: String,
    expected_serial: Option<Serial>,
    result: Result<Serial, ProbeSoaError>,
) -> SecondaryStatusResponse {
    match result {
        Ok(visible) => {
            let status = match expected_serial {
                Some(expected) if visible == expected => SecondaryStatus::InSync,
                Some(expected) if visible.is_newer_than(expected) => SecondaryStatus::Ahead,
                Some(expected) if expected.is_newer_than(visible) => SecondaryStatus::Lagging,
                // RFC 1982, Section 3.2: half-range distances have no ordering.
                Some(_) => SecondaryStatus::Reachable,
                None => SecondaryStatus::Reachable,
            };
            SecondaryStatusResponse {
                address,
                status,
                visible_serial: Some(visible),
                error: None,
                last_transfer: None,
            }
        }
        Err(error) => SecondaryStatusResponse {
            address,
            status: SecondaryStatus::Unreachable,
            visible_serial: None,
            error: Some(error.to_string()),
            last_transfer: None,
        },
    }
}

/// Probe enabled secondaries in parallel against `expected_serial`;
/// return an empty list if none are enabled.
pub async fn probe_secondaries(
    cx: &Context,
    zone_name: &ZoneName,
    expected_serial: Option<Serial>,
) -> Result<Vec<SecondaryStatusResponse>, ServiceError> {
    let secondaries = secondary::list_enabled(cx).await?;
    if secondaries.is_empty() {
        return Ok(Vec::new());
    }

    let timeout = cx.config().dns.notify.timeout();

    // The network half owns its inputs, so each probe runs on a task of its
    // own; the transfer lookup that needs the context follows on this one.
    let mut tasks = Vec::new();
    for secondary in secondaries {
        let zone_name = zone_name.clone();
        tasks.push((
            secondary.address.to_string(),
            tokio::spawn(async move {
                probe_addresses(&zone_name, &secondary, timeout, expected_serial).await
            }),
        ));
    }

    let mut probes = Vec::new();
    for (address, task) in tasks {
        match task.await {
            Ok(Ok((probe, clients))) => {
                probes.push(attach_last_transfer(cx, zone_name, probe, &clients).await)
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(e) => probes.push(build_secondary_status(
                address,
                expected_serial,
                Err(ProbeSoaError::TaskFailed(e)),
            )),
        }
    }

    Ok(probes)
}

/// Probe one secondary at each resolved address until one answers,
/// then compare with `expected_serial`.
pub async fn probe_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
    expected_serial: Option<Serial>,
) -> Result<SecondaryStatusResponse, ServiceError> {
    let timeout = cx.config().dns.notify.timeout();
    let (probe, clients) = probe_addresses(zone_name, secondary, timeout, expected_serial).await?;
    Ok(attach_last_transfer(cx, zone_name, probe, &clients).await)
}

/// Resolve and probe a secondary without daemon state.
/// Return resolved addresses for transfer-row lookups.
async fn probe_addresses(
    zone_name: &ZoneName,
    secondary: &Secondary,
    timeout: Duration,
    expected_serial: Option<Serial>,
) -> Result<(SecondaryStatusResponse, Vec<IpAddr>), ProbeSoaError> {
    let qname = zone_name.to_wire_name()?;

    let addrs = match super::resolve_address_entry(&secondary.address, timeout).await {
        Ok(addrs) => addrs,
        Err(e) => {
            return Ok((
                build_secondary_status(
                    secondary.address.to_string(),
                    expected_serial,
                    Err(ProbeSoaError::Resolve(e)),
                ),
                Vec::new(),
            ));
        }
    };
    let (probe, clients) = probe_entry(&qname, addrs, timeout, expected_serial).await;
    // The resolver hands back at least one address, so this stands in for none.
    let probe = probe.unwrap_or_else(|| {
        build_secondary_status(
            secondary.address.to_string(),
            expected_serial,
            Err(ProbeSoaError::Resolve(ResolveAddressError::NoAddresses)),
        )
    });
    Ok((probe, clients))
}

/// Attach what Bindizr last sent the secondary for the zone, beside what it
/// serves now; a secondary that did not resolve keys no transfer row.
async fn attach_last_transfer(
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
) -> Result<Serial, ProbeSoaError> {
    let qname = zone_name.to_wire_name()?;
    probe_address(&qname, server_addr, timeout).await
}

/// Probe addresses in order; return the first answer or last failure and the addresses tried.
/// Try beyond the first address to match NOTIFY and transfer ACL resolution.
async fn probe_entry(
    qname: &Name<Vec<u8>>,
    addrs: Vec<SocketAddr>,
    timeout: Duration,
    expected_serial: Option<Serial>,
) -> (Option<SecondaryStatusResponse>, Vec<IpAddr>) {
    let clients: Vec<IpAddr> = addrs.iter().map(|addr| addr.ip()).collect();
    let mut last = None;
    for addr in addrs {
        match probe_address(qname, addr, timeout).await {
            Ok(serial) => {
                last = Some(build_secondary_status(
                    addr.to_string(),
                    expected_serial,
                    Ok(serial),
                ));
                break;
            }
            Err(e) => {
                last = Some(build_secondary_status(
                    addr.to_string(),
                    expected_serial,
                    Err(e),
                ))
            }
        }
    }

    (last, clients)
}

/// Query one address for the zone's authoritative SOA serial.
async fn probe_address(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<Serial, ProbeSoaError> {
    let (query_id, builder) = build_question(Opcode::QUERY, false, false, qname, Rtype::SOA, None);
    let query = builder.finish();
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
