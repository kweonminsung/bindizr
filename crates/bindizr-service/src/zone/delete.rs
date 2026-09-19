use bindizr_core::dns::CATALOG_ZONE_NAME;
use bindizr_db::repository::{LockLevel, RecordFilter};

use super::ZoneService;
use crate::{
    authorization::Caller,
    error::ServiceError,
    repository::RepositoryService,
    types::{DeleteZoneResponse, GetZoneResponse},
};

impl ZoneService {
    /// Delete a zone by name and NOTIFY the catalog zone after commit. A dry
    /// run reports what the zone holds and removes nothing, since the delete
    /// takes the records and the rollback history with it.
    pub async fn delete(
        caller: &Caller,
        zone_name: &str,
        dry_run: bool,
    ) -> Result<DeleteZoneResponse, ServiceError> {
        caller.authorize_global("delete zones")?;

        let mut tx = RepositoryService::begin_tx("Failed to delete zone").await?;

        let apply_result = async {
            // Locked lookup so a raced double-delete reports 404, not success.
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;

            // Counted for the report, not acted on, so they run unlocked.
            let records = RepositoryService::count_records_by_filter(RecordFilter {
                zone_name: Some(zone.name.to_string()),
                ..RecordFilter::default()
            })
            .await?;
            let versions = RepositoryService::count_zone_versions(zone.id, false).await?;

            let response = DeleteZoneResponse {
                applied: !dry_run,
                dry_run,
                zone: GetZoneResponse::from_zone(&zone),
                records,
                versions,
            };
            if dry_run {
                return Ok(response);
            }

            RepositoryService::delete_zone_tx(&mut tx, zone.id)
                .await
                .map_err(|e| {
                    log::error!("Failed to delete zone: {}", e);
                    ServiceError::internal("Failed to delete zone")
                })?;
            log::info!("event=zone_delete zone={} zone_id={}", zone.name, zone.id);
            Ok(response)
        }
        .await;

        let response =
            RepositoryService::finish_tx(tx, apply_result, "Failed to delete zone").await?;

        // Send catalog NOTIFY so secondaries drop the removed zone
        if response.applied
            && let Err(e) = crate::notify::send_notify_after_update(Some(CATALOG_ZONE_NAME)).await
        {
            log::warn!("Failed to send NOTIFY for {}: {}", CATALOG_ZONE_NAME, e);
        }

        Ok(response)
    }
}
