use super::error::XfrError;
use crate::service::zone::{ZoneService, snapshot};

pub(crate) type ZoneChange = bindizr_core::model::zone_change::ZoneChange;
pub(crate) type ZoneSnapshot = bindizr_core::model::zone_snapshot::ZoneSnapshot;

/// Get zone changes between two serials for IXFR
pub(crate) async fn get_zone_changes(
    zone_id: i32,
    from_serial: u32,
    to_serial: u32,
) -> Result<Vec<ZoneChange>, XfrError> {
    ZoneService::get_changes_between_serials(zone_id, from_serial as i32, to_serial as i32)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))
}

pub(crate) async fn get_zone_snapshot(
    zone_id: i32,
    serial: u32,
) -> Result<Option<ZoneSnapshot>, XfrError> {
    snapshot::get_by_serial(zone_id, serial as i32)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))
}

pub(crate) fn serial_to_u32(serial: i32) -> Result<u32, XfrError> {
    u32::try_from(serial)
        .map_err(|_| XfrError::ProtocolError(format!("Invalid DNS serial: {}", serial)))
}
