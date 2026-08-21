use chrono::Utc;

use super::ZoneService;
use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    metrics::metrics,
    model::{zone::Zone, zone_version::ZoneVersion},
    repository::RepositoryService,
};

impl ZoneService {
    /// Advance the zone serial so IXFR consumers detect the change, and
    /// version it in the same transaction.
    pub(crate) async fn advance_serial_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        new_serial: i32,
    ) -> Result<(), ServiceError> {
        RepositoryService::update_zone_serial_tx(tx, zone.id, new_serial)
            .await
            .map_err(|e| {
                log_error!("Failed to update zone serial: {}", e);
                ServiceError::internal("Failed to update zone serial".to_string())
            })?;

        Self::save_version_tx(tx, zone, new_serial).await
    }

    /// Save a version of the zone's SOA data for historical tracking.
    pub(crate) async fn save_version_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        serial: i32,
    ) -> Result<(), ServiceError> {
        RepositoryService::upsert_zone_version_tx(
            tx,
            ZoneVersion {
                id: 0,
                zone_id: zone.id,
                serial,
                mname: zone.mname.clone(),
                rname: zone
                    .soa_mailbox()
                    .map_err(ServiceError::invalid_zone_field)?
                    .into_encoded(),
                default_ttl: zone.default_ttl,
                refresh: zone.refresh,
                retry: zone.retry,
                expire: zone.expire,
                minimum_ttl: zone.minimum_ttl,
                created_at: Utc::now(),
            },
        )
        .await
        .map_err(|e| {
            log_error!("Failed to save SOA version: {}", e);
            ServiceError::internal("Failed to save SOA version".to_string())
        })?;

        // Every serial-advancing path funnels through this version write; count
        // bumps here. Incremented pre-commit: a later rollback overcounts, which
        // is acceptable for a monitoring counter.
        metrics().zone_serial_bumps_total.inc();

        Ok(())
    }

    /// Fetch the SOA version recorded for a zone at the given serial, if any.
    pub async fn find_version_by_serial(
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneVersion>, ServiceError> {
        RepositoryService::get_zone_version_by_serial(zone_id, serial).await
    }

    /// Fetch every SOA version for a zone with serial in `[from_serial, to_serial]`.
    pub async fn list_versions_in_serial_range(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneVersion>, ServiceError> {
        RepositoryService::list_zone_versions_in_serial_range(zone_id, from_serial, to_serial).await
    }
}
