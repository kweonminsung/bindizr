//! A zone's serial next to what each enabled secondary is serving.

use bindizr_core::{dns::name::ZoneName, model::role_grant::Action};

use crate::{
    Context, authorization::Caller, dns_client::probe, error::ServiceError,
    types::ZoneStatusResponse,
};

/// Probe every enabled secondary for the zone and classify each
/// against the zone's serial; empty with no enabled secondaries.
pub async fn get_status(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<ZoneStatusResponse, ServiceError> {
    // Read once: a write landing during the probe can show a secondary as
    // ahead for a moment, the drift a read-only path accepts.
    let zone = super::get_by_name(cx, caller, zone_name).await?;
    caller.authorize_zone_action(Action::ZoneRead, &zone)?;

    let serial = zone.serial;
    let secondaries = probe::probe_secondaries(cx, &zone.name, Some(serial)).await?;

    Ok(ZoneStatusResponse {
        zone_name: zone.name.to_string(),
        serial,
        secondaries,
    })
}
