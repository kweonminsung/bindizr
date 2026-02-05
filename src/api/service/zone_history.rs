use crate::{
    api::error::ApiError,
    database::{get_zone_history_repository, model::zone_history::ZoneHistory},
    log_error,
};

#[derive(Clone)]
pub struct ZoneHistoryService;

impl ZoneHistoryService {
    pub async fn get_zone_histories(zone_name: &str) -> Result<Vec<ZoneHistory>, ApiError> {
        let zone_history_repository = get_zone_history_repository();

        let zone_histories = zone_history_repository
            .get_by_zone_name(zone_name)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch zone histories: {}", e);
                ApiError::InternalServerError("Failed to fetch zone histories".to_string())
            })?;

        Ok(zone_histories)
    }
}
