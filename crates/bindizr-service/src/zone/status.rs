//! A zone's serial next to what each configured secondary is serving.

use super::ZoneService;
use crate::{
    authorization::Caller, dns_client::probe, error::ServiceError, types::ZoneStatusResponse,
};

impl ZoneService {
    /// Probe every configured secondary for the zone and classify each
    /// against the zone's serial; empty with no secondaries configured.
    pub async fn get_status(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<ZoneStatusResponse, ServiceError> {
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
