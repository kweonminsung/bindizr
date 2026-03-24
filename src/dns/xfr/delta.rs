use super::error::XfrError;
use crate::service::repository::RepositoryService;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSnapshot {
    pub primary_ns: String,
    pub admin_email: String,
    pub ttl: i32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum_ttl: i32,
    pub serial: u32,
}

/// Get zone changes between two serials for IXFR
pub async fn get_zone_changes(
    zone_id: i32,
    from_serial: u32,
    to_serial: u32,
) -> Result<Vec<ZoneChange>, XfrError> {
    let changes = RepositoryService::get_zone_changes_between_serials(
        zone_id,
        from_serial as i32,
        to_serial as i32,
    )
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

pub async fn get_zone_snapshot(
    zone_id: i32,
    serial: u32,
) -> Result<Option<ZoneSnapshot>, XfrError> {
    let snapshot = RepositoryService::get_zone_snapshot_by_serial(zone_id, serial as i32)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    Ok(snapshot.map(|s| ZoneSnapshot {
        primary_ns: s.primary_ns,
        admin_email: s.admin_email,
        ttl: s.ttl,
        refresh: s.refresh,
        retry: s.retry,
        expire: s.expire,
        minimum_ttl: s.minimum_ttl,
        serial: s.serial as u32,
    }))
}
