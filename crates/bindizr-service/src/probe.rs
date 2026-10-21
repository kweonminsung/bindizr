//! Secondary SOA status and transfer history.
use std::net::IpAddr;

use bindizr_core::dns::{Serial, name::ZoneName};

use crate::{
    Context,
    dns_client::probe::{ProbeSoaError, probe_addresses},
    error::ServiceError,
    model::secondary::Secondary,
    secondary, transfer,
    types::{SecondaryStatus, SecondaryStatusResponse, TransferResponse},
};

impl From<ProbeSoaError> for ServiceError {
    /// Preserve probe setup failures as internal error sources.
    fn from(err: ProbeSoaError) -> Self {
        ServiceError::Internal {
            message: err.to_string(),
            source: Some(Box::new(err)),
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

    let mut tasks = Vec::new();
    for secondary in secondaries {
        let zone_name = zone_name.clone();
        tasks.push((
            secondary.address.to_string(),
            tokio::spawn(
                async move { probe_addresses(&zone_name, &secondary.address, timeout).await },
            ),
        ));
    }

    let mut probes = Vec::new();
    for (address, task) in tasks {
        match task.await {
            Ok(Ok(probe)) => {
                let status = build_secondary_status(probe.address, expected_serial, probe.serial);
                probes.push(attach_last_transfer(cx, zone_name, status, &probe.clients).await)
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

/// Probe one secondary and attach its serial status and transfer history.
pub async fn probe_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
    expected_serial: Option<Serial>,
) -> Result<SecondaryStatusResponse, ServiceError> {
    let timeout = cx.config().dns.notify.timeout();
    let probe = probe_addresses(zone_name, &secondary.address, timeout).await?;
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
            Err(e) => {
                log::warn!("Failed to read the transfers of {}: {}", zone_name, e);
                None
            }
        };
    probe
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Serial ordering survives wraparound; half-range differences remain unordered.
    #[test]
    fn secondary_status_uses_rfc1982_order() {
        for (expected, visible, status) in [
            (0, u32::MAX, SecondaryStatus::Lagging),
            (u32::MAX, 0, SecondaryStatus::Ahead),
            (0, 0, SecondaryStatus::InSync),
            (0, 0x8000_0000, SecondaryStatus::Reachable),
        ] {
            assert_eq!(
                build_secondary_status(
                    "server".into(),
                    Some(Serial::from(expected)),
                    Ok(Serial::from(visible))
                )
                .status,
                status
            );
        }
    }
}
