//! A zone's serial next to what each enabled secondary is serving.

use super::ZoneService;
use crate::{
    authorization::Caller, dns_client::probe, error::ServiceError, types::ZoneStatusResponse,
};

impl ZoneService {
    /// Probe every enabled secondary for the zone and classify each
    /// against the zone's serial; empty with no enabled secondaries.
    pub async fn get_status(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<ZoneStatusResponse, ServiceError> {
        // Read once: a write landing during the probe can show a secondary as
        // ahead for a moment, the drift a read-only path accepts.
        let zone = Self::get_by_name(caller, zone_name).await?;

        let probes = probe::probe_secondaries(zone.name.as_str())
            .await
            .map_err(ServiceError::internal)?;

        Ok(ZoneStatusResponse::from_probes(
            &zone,
            probes.into_iter().map(|p| (p.address, p.result)),
        ))
    }
}
