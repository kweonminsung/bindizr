use bindizr_core::dns::{CATALOG_ZONE_NAME, name::ZoneName};
use bindizr_db::repository::LockLevel;

use super::ZoneService;
use crate::{
    authorization::Caller, error::ServiceError, log_error, log_info, log_warn,
    repository::RepositoryService,
};

impl ZoneService {
    /// Delete a zone by name and NOTIFY the catalog zone after commit.
    pub async fn delete(caller: &Caller, zone_name: &str) -> Result<(), ServiceError> {
        caller.require_global("delete zones")?;

        let mut tx = RepositoryService::begin_tx("Failed to delete zone").await?;

        let apply_result = async {
            // Locked lookup so a raced double-delete reports 404, not success.
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;

            RepositoryService::delete_zone_tx(&mut tx, zone.id)
                .await
                .map_err(|e| {
                    log_error!("Failed to delete zone: {}", e);
                    ServiceError::internal("Failed to delete zone".to_string())
                })?;
            Ok::<(i32, ZoneName), ServiceError>((zone.id, zone.name))
        }
        .await;

        let (zone_id, zone_name) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to delete zone").await?;

        log_info!("event=zone_delete zone={} zone_id={}", zone_name, zone_id);

        // Send catalog NOTIFY so secondaries drop the removed zone
        if let Err(e) = crate::notify::send_notify_after_update(Some(CATALOG_ZONE_NAME)).await {
            log_warn!("Failed to send NOTIFY for {}: {}", CATALOG_ZONE_NAME, e);
        }

        Ok(())
    }
}
