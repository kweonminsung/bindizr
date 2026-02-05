use crate::{
    api::error::ApiError,
    database::{get_record_history_repository, model::record_history::RecordHistory},
    log_error,
};

#[derive(Clone)]
pub struct RecordHistoryService;

impl RecordHistoryService {
    pub async fn get_record_histories(
        name: &str,
        record_type: &str,
    ) -> Result<Vec<RecordHistory>, ApiError> {
        let record_history_repository = get_record_history_repository();

        let record_histories = record_history_repository
            .get_by_record_name_and_type(name, record_type)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch record histories: {}", e);
                ApiError::InternalServerError("Failed to fetch record histories".to_string())
            })?;

        Ok(record_histories)
    }
}
