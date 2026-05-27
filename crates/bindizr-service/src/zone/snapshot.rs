use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    model::{zone::Zone, zone_snapshot::ZoneSnapshot},
    repository::RepositoryService,
};
use chrono::Utc;

/// Save a snapshot of the zone's SOA data for historical tracking.
pub async fn save_zone_snapshot_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    serial: i32,
) -> Result<(), ServiceError> {
    RepositoryService::upsert_zone_snapshot_tx(
        tx,
        ZoneSnapshot {
            id: 0,
            zone_id: zone.id,
            serial,
            primary_ns: zone.primary_ns.clone(),
            admin_email: zone.admin_email.replace('@', "."),
            ttl: zone.ttl,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: zone.minimum_ttl,
            created_at: Utc::now(),
        },
    )
    .await
    .map_err(|e| {
        log_error!("Failed to save SOA snapshot: {}", e);
        ServiceError::Internal("Failed to save SOA snapshot".to_string())
    })?;

    Ok(())
}

pub async fn get_by_serial(
    zone_id: i32,
    serial: i32,
) -> Result<Option<ZoneSnapshot>, ServiceError> {
    RepositoryService::get_zone_snapshot_by_serial(zone_id, serial).await
}
