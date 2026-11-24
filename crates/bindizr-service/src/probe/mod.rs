//! Secondary SOA status and transfer history.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::secondary::Secondary;
use tokio::task::JoinSet;

use crate::dns_client::soa::{ProbeSoaError, SoaProbe};
use crate::error::ServiceError;
use crate::secondary::SecondaryTarget;
use crate::types::{SecondaryStatus, SecondaryStatusResponse, TransferLogResponse};
use crate::{Context, dns_client, secondary, transfer};

/// Classify SOA results; failed probes are unreachable, incomparable serials reachable.
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

/// Probe enabled secondaries in parallel and attach their transfer history.
pub async fn probe_secondaries(
    cx: &Context,
    zone_name: &ZoneName,
    expected_serial: Option<Serial>,
) -> Result<Vec<SecondaryStatusResponse>, ServiceError> {
    let targets = secondary::resolve_enabled(cx).await?;
    probe_targets(cx, zone_name, &targets, expected_serial).await
}

/// Probe targets resolved by the owning diagnostic request, preserving their order.
pub(crate) async fn probe_targets(
    cx: &Context,
    zone_name: &ZoneName,
    targets: &[SecondaryTarget],
    expected_serial: Option<Serial>,
) -> Result<Vec<SecondaryStatusResponse>, ServiceError> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let timeout = cx.config().dns.notify.timeout();

    let mut tasks = JoinSet::new();
    let mut target_indices = HashMap::new();

    for (index, target) in targets.iter().cloned().enumerate() {
        let zone_name = zone_name.clone();
        let task = tasks.spawn(async move { probe_resolved(&zone_name, &target, timeout).await });
        target_indices.insert(task.id(), index);
    }

    let mut statuses = Vec::new();

    // The set owns every exchange, including when this request is cancelled.
    while let Some(result) = tasks.join_next_with_id().await {
        let id = match &result {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        // Every id belongs to this set and was registered before joining.
        let index = target_indices[&id];
        let target = &targets[index];
        let status = match result {
            Ok((_, Ok(probe))) => {
                let status = build_secondary_status(probe.address, expected_serial, probe.serial);
                attach_last_transfer(cx, zone_name, status, &target.client_ips()).await?
            }
            Ok((_, Err(error))) => return Err(error),
            Err(error) => SecondaryStatusResponse {
                address: target.secondary.address.to_string(),
                status: SecondaryStatus::Unreachable,
                visible_serial: None,
                error: Some(format!("probe task failed: {error}")),
                last_transfer: None,
            },
        };
        statuses.push((index, status));
    }

    statuses.sort_unstable_by_key(|(index, _)| *index);
    Ok(statuses.into_iter().map(|(_, status)| status).collect())
}

/// Probe one secondary and attach its serial status and transfer history.
pub async fn probe_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
    expected_serial: Option<Serial>,
) -> Result<SecondaryStatusResponse, ServiceError> {
    let target =
        SecondaryTarget::resolve(secondary.clone(), cx.config().dns.notify.timeout()).await;
    probe_target(cx, zone_name, &target, expected_serial).await
}

/// Probe one request-owned target and attach history for the same resolved IPs.
pub(crate) async fn probe_target(
    cx: &Context,
    zone_name: &ZoneName,
    target: &SecondaryTarget,
    expected_serial: Option<Serial>,
) -> Result<SecondaryStatusResponse, ServiceError> {
    let probe = probe_resolved(zone_name, target, cx.config().dns.notify.timeout()).await?;
    let status = build_secondary_status(probe.address, expected_serial, probe.serial);
    attach_last_transfer(cx, zone_name, status, &target.client_ips()).await
}

/// Probe the request's addresses or report its original resolution failure.
async fn probe_resolved(
    zone_name: &ZoneName,
    target: &SecondaryTarget,
    timeout: Duration,
) -> Result<SoaProbe, ServiceError> {
    match &target.addresses {
        Ok(addrs) => {
            dns_client::soa::probe_addresses(zone_name, &target.secondary.address, addrs, timeout)
                .await
                .map_err(|error| {
                    ServiceError::internal_with_source("the SOA probe could not start", error)
                })
        }
        Err(error) => Ok(SoaProbe {
            address: target.secondary.address.to_string(),
            serial: Err(ProbeSoaError::Resolve(error.clone().into())),
        }),
    }
}

/// Attach the latest zone transfer matching the probe's resolved IPs. The
/// catalog has none: it is virtual, with no zone row a log row could name.
async fn attach_last_transfer(
    cx: &Context,
    zone_name: &ZoneName,
    mut status: SecondaryStatusResponse,
    clients: &[IpAddr],
) -> Result<SecondaryStatusResponse, ServiceError> {
    if clients.is_empty() || zone_name == &cx.config().dns.catalog_zone_name {
        return Ok(status);
    }

    status.last_transfer = transfer::find_by_clients_and_zone_name(cx, clients, zone_name)
        .await?
        .as_ref()
        .map(TransferLogResponse::from);

    Ok(status)
}

#[cfg(test)]
mod tests;
