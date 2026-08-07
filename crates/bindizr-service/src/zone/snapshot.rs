use chrono::Utc;

use super::ZoneService;
use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    metrics::metrics,
    model::{zone::Zone, zone_snapshot::ZoneSnapshot},
    repository::RepositoryService,
};

impl ZoneService {
    /// Save a snapshot of the zone's SOA data for historical tracking.
    pub async fn save_snapshot_tx(
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
                admin_email: zone
                    .soa_mailbox()
                    .map_err(|e| ServiceError::invalid_zone(e.to_string()))?,
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
            ServiceError::internal("Failed to save SOA snapshot".to_string())
        })?;

        // Every serial-advancing path funnels through this snapshot write; count
        // bumps here. Incremented pre-commit: a later rollback overcounts, which
        // is acceptable for a monitoring counter.
        metrics().zone_serial_bumps_total.inc();

        Ok(())
    }

    /// Fetch the SOA snapshot recorded for a zone at the given serial, if any.
    pub async fn find_snapshot_by_serial(
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneSnapshot>, ServiceError> {
        RepositoryService::get_zone_snapshot_by_serial(zone_id, serial).await
    }

    /// Fetch every SOA snapshot for a zone with serial in `[from_serial, to_serial]`.
    pub async fn list_snapshots_in_range(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneSnapshot>, ServiceError> {
        RepositoryService::get_zone_snapshots_in_range(zone_id, from_serial, to_serial).await
    }
}
