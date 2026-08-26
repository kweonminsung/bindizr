//! A zone's serial next to what each configured secondary is serving.
//! Answering that needs both the zone row and a live SOA probe, and the
//! service layer sits below this crate, so it lives here — the HTTP API and
//! the daemon socket both call in rather than each assembling it.

use bindizr_service::{
    authorization::Caller, error::ServiceError, types::ZoneStatusResponse, zone::ZoneService,
};

use crate::dns::client::probe;

/// Probe every configured secondary for `zone_name` and classify each against
/// the zone's serial. With no secondaries configured the list is empty.
pub(crate) async fn zone_status(
    caller: &Caller,
    zone_name: &str,
) -> Result<ZoneStatusResponse, ServiceError> {
    let zone = ZoneService::get_by_name(caller, zone_name).await?;

    let probes = probe::probe_secondaries(zone.name.as_str())
        .await
        .map_err(|e| ServiceError::internal(e.to_string()))?;

    Ok(ZoneStatusResponse::from_probes(
        &zone,
        probes.into_iter().map(|p| (p.address, p.result)),
    ))
}
