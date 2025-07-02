use crate::{
    database::{
        get_record_history_repository, get_record_repository, model::record_history::RecordHistory,
    },
    log_error,
};

#[derive(Clone)]
pub struct RecordHistoryService;

impl RecordHistoryService {
    pub async fn get_record_histories(record_id: i32) -> Result<Vec<RecordHistory>, String> {
        let record_repository = get_record_repository();
        let record_history_repository = get_record_history_repository();

        // Check if the record exists
        match record_repository.get_by_id(record_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err("Record not found".to_string());
            }
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err("Failed to fetch record".to_string());
            }
        };

        let record_histories = record_history_repository
            .get_by_record_id(record_id)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch record histories: {}", e);
                "Failed to fetch record histories".to_string()
            })?;

        Ok(record_histories)
    }

    pub async fn delete_record_history(record_history_id: i32) -> Result<(), String> {
        let record_history_repository = get_record_history_repository();

        // Check if the record history exists
        match record_history_repository.get_by_id(record_history_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err("Record history not found".to_string());
            }
            Err(e) => {
                log_error!("Failed to fetch record history: {}", e);
                return Err("Failed to fetch record history".to_string());
            }
        };

        // Delete the record history
        if let Err(e) = record_history_repository.delete(record_history_id).await {
            log_error!("Failed to delete record history: {}", e);
            return Err("Failed to delete record history".to_string());
        };

        Ok(())
    }
}
