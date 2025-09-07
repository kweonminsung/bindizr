use crate::{
    database::{
        get_zone_history_repository, get_zone_repository, model::zone_history::ZoneHistory,
    },
    log_error,
};

#[derive(Clone)]
pub struct ZoneHistoryService;

impl ZoneHistoryService {
    pub async fn get_zone_histories(zone_id: i32) -> Result<Vec<ZoneHistory>, String> {
        let zone_repository = get_zone_repository();
        let zone_history_repository = get_zone_history_repository();

        // Check if the zone exists
        match zone_repository.get_by_id(zone_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err("Zone not found".to_string());
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err("Failed to fetch zone".to_string());
            }
        };

        let zone_histories = zone_history_repository
            .get_by_zone_id(zone_id)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch zone histories: {}", e);
                "Failed to fetch zone histories".to_string()
            })?;

        Ok(zone_histories)
    }

    pub async fn delete_zone_history(zone_history_id: i32) -> Result<(), String> {
        let zone_history_repository = get_zone_history_repository();

        // Check if the zone history exists
        match zone_history_repository.get_by_id(zone_history_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err("Zone history not found".to_string());
            }
            Err(e) => {
                log_error!("Failed to fetch zone history: {}", e);
                return Err("Failed to fetch zone history".to_string());
            }
        };

        // Delete the zone history
        if let Err(e) = zone_history_repository.delete(zone_history_id).await {
            log_error!("Failed to delete zone history: {}", e);
            return Err("Failed to delete zone history".to_string());
        };

        Ok(())
    }
}
