use bindizr_core::dns::CATALOG_ZONE_NAME;

use super::{ZoneService, validation::normalize_zone_name};
use crate::{error::ServiceError, log_error, log_info, log_warn, repository::RepositoryService};

impl ZoneService {
    /// Delete a zone by name and NOTIFY the catalog zone after commit.
    pub async fn delete(zone_name: &str) -> Result<(), ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;

        let mut tx = RepositoryService::begin_tx("Failed to delete zone").await?;

        let apply_result = async {
            // Locked lookup so a raced double-delete reports 404, not success.
            let zone = match RepositoryService::get_zone_by_name_tx(&mut tx, &lookup_name).await {
                Ok(Some(z)) => z,
                Ok(None) => {
                    log_error!("Zone with name '{}' not found", zone_name);
                    return Err(ServiceError::zone_not_found(zone_name));
                }
                Err(e) => {
                    log_error!("Failed to fetch zone: {}", e);
                    return Err(ServiceError::internal("Failed to delete zone".to_string()));
                }
            };

            RepositoryService::delete_zone_tx(&mut tx, zone.id)
                .await
                .map_err(|e| {
                    log_error!("Failed to delete zone: {}", e);
                    ServiceError::internal("Failed to delete zone".to_string())
                })?;
            Ok::<(i32, String), ServiceError>((zone.id, zone.name))
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
