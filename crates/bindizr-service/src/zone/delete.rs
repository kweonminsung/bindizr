use crate::{error::ServiceError, log_error, log_info, log_warn, repository::RepositoryService};

use super::ZoneService;

impl ZoneService {
    pub async fn delete(zone_name: &str) -> Result<(), ServiceError> {
        // Check if zone exists and get its ID
        let zone = match RepositoryService::get_zone_by_name(zone_name).await {
            Ok(Some(z)) => z,
            Ok(None) => {
                log_error!("Zone with name '{}' not found", zone_name);
                return Err(ServiceError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ServiceError::Internal("Failed to delete zone".to_string()));
            }
        };

        let zone_id = zone.id;
        let zone_name_clone = zone.name.clone();

        // Delete zone
        let mut tx = RepositoryService::begin_tx("Failed to delete zone").await?;

        let apply_result = async {
            RepositoryService::delete_zone_tx(&mut tx, zone_id)
                .await
                .map_err(|e| {
                    log_error!("Failed to delete zone: {}", e);
                    ServiceError::Internal("Failed to delete zone".to_string())
                })?;
            Ok::<(), ServiceError>(())
        }
        .await;

        RepositoryService::finish_tx(tx, apply_result, "Failed to delete zone").await?;

        // Log zone deletion after commit (structured logging)
        log_info!(
            "event=zone_delete zone={} zone_id={}",
            zone_name_clone,
            zone_id
        );

        if let Err(e) = crate::notify::send_notify(Some("catalog.bind")).await {
            log_warn!("Failed to send NOTIFY for catalog.bind: {}", e);
        }

        Ok(())
    }
}
