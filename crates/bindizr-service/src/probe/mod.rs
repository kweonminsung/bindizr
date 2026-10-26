//! Secondary SOA status and transfer history.
use std::collections::HashMap;
use std::net::IpAddr;

use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use tokio::task::JoinSet;

use crate::dns_client::probe;
use crate::dns_client::probe::ProbeSoaError;
use crate::error::ServiceError;
use crate::model::secondary::Secondary;
use crate::types::{SecondaryStatus, SecondaryStatusResponse, TransferResponse};
use crate::{Context, secondary, transfer};

impl From<ProbeSoaError> for ServiceError {
    /// Preserve probe setup failures as internal error sources.
    fn from(error: ProbeSoaError) -> Self {
        ServiceError::Internal {
            message: error.to_string(),
            source: Some(Box::new(error)),
        }
    }
}

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
    let secondaries = secondary::list_enabled(cx).await?;

    if secondaries.is_empty() {
        return Ok(Vec::new());
    }

    let timeout = cx.config().dns.notify.timeout();

    let mut tasks = JoinSet::new();
    let mut targets = HashMap::new();

    for (index, secondary) in secondaries.into_iter().enumerate() {
        let zone_name = zone_name.clone();
        let address = secondary.address.to_string();

        let task = tasks.spawn(async move {
            probe::probe_addresses(&zone_name, &secondary.address, timeout).await
        });
        targets.insert(task.id(), (index, address));
    }

    let mut probes = Vec::new();

    // The set owns every exchange, including when this request is cancelled.
    while let Some(result) = tasks.join_next_with_id().await {
        let id = match &result {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        // Every id belongs to this set and was registered before joining.
        let (index, address) = &targets[&id];
        let status = match result {
            Ok((_, Ok(probe))) => {
                let status = build_secondary_status(probe.address, expected_serial, probe.serial);
                attach_last_transfer(cx, zone_name, status, &probe.clients).await
            }
            Ok((_, Err(error))) => return Err(error.into()),
            Err(error) => SecondaryStatusResponse {
                address: address.clone(),
                status: SecondaryStatus::Unreachable,
                visible_serial: None,
                error: Some(format!("probe task failed: {error}")),
                last_transfer: None,
            },
        };
        probes.push((*index, status));
    }

    probes.sort_unstable_by_key(|(index, _)| *index);
    Ok(probes.into_iter().map(|(_, probe)| probe).collect())
}

/// Probe one secondary and attach its serial status and transfer history.
pub async fn probe_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
    expected_serial: Option<Serial>,
) -> Result<SecondaryStatusResponse, ServiceError> {
    let timeout = cx.config().dns.notify.timeout();
    let probe = probe::probe_addresses(zone_name, &secondary.address, timeout).await?;
    let status = build_secondary_status(probe.address, expected_serial, probe.serial);
    Ok(attach_last_transfer(cx, zone_name, status, &probe.clients).await)
}

/// Attach the latest zone transfer matching the probe's resolved IPs.
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
            Err(error) => {
                log::warn!("Failed to read the transfers of {}: {}", zone_name, error);
                None
            }
        };

    probe
}

#[cfg(test)]
mod tests;
