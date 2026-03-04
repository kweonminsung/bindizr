use super::error::XfrError;
use crate::database::get_zone_change_repository;

#[derive(Debug, Clone)]
pub struct ZoneChange {
    pub serial: u32,
    pub operation: String, // "ADD" or "DEL"
    pub record_name: String,
    pub record_type: String,
    pub record_value: String,
    pub record_ttl: Option<i32>,
    pub record_priority: Option<i32>,
}

/// Get zone changes between two serials for IXFR
pub async fn get_zone_changes(
    zone_id: i32,
    from_serial: u32,
    to_serial: u32,
) -> Result<Vec<ZoneChange>, XfrError> {
    let repo = get_zone_change_repository();

    let changes = repo
        .get_changes_between_serials(zone_id, from_serial as i32, to_serial as i32)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    // Convert database model to XFR ZoneChange
    let xfr_changes = changes
        .into_iter()
        .map(|change| ZoneChange {
            serial: change.serial as u32,
            operation: change.operation,
            record_name: change.record_name,
            record_type: change.record_type,
            record_value: change.record_value,
            record_ttl: change.record_ttl,
            record_priority: change.record_priority,
        })
        .collect();

    Ok(xfr_changes)
}
