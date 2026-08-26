//! IXFR delta computation: the zone changes between two serials.

use bindizr_service::zone::ZoneService;

use crate::dns::error::XfrError;

pub(crate) type ZoneChange = bindizr_core::model::zone_change::ZoneChange;
pub(crate) type ZoneVersion = bindizr_core::model::zone_version::ZoneVersion;

/// Zone changes between two serials, for IXFR.
pub(crate) async fn list_zone_journal(
    zone_id: i32,
    from_serial: u32,
    to_serial: u32,
) -> Result<Vec<ZoneChange>, XfrError> {
    ZoneService::list_journal_between_serials(zone_id, from_serial as i32, to_serial as i32)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))
}

pub(crate) async fn find_zone_version(
    zone_id: i32,
    serial: u32,
) -> Result<Option<ZoneVersion>, XfrError> {
    ZoneService::find_version_by_serial(zone_id, serial as i32)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))
}

/// Fetch every version for a zone with serial in `[from_serial, to_serial]`.
pub(crate) async fn list_zone_versions(
    zone_id: i32,
    from_serial: u32,
    to_serial: u32,
) -> Result<Vec<ZoneVersion>, XfrError> {
    ZoneService::list_versions_in_serial_range(zone_id, from_serial as i32, to_serial as i32)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))
}
