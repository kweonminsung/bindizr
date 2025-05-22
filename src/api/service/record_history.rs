use mysql::prelude::Queryable;

use crate::database::{model::record_history::RecordHistory, DatabasePool};

use super::common::CommonService;

#[derive(Clone)]
pub struct RecordHistoryService;

impl RecordHistoryService {
    fn get_record_history_by_id(
        pool: &DatabasePool,
        record_history_id: i32,
    ) -> Result<RecordHistory, String> {
        let mut conn = pool.get_connection();

        let record_history = conn
            .exec_first(
                "SELECT * FROM record_history WHERE id = ?",
                (record_history_id,),
            )
            .map_err(|e| format!("Failed to fetch record history: {}", e))?
            .ok_or_else(|| "Record history not found".to_string())?;

        Ok(RecordHistory::from_row(record_history))
    }

    pub fn get_record_histories(
        pool: &DatabasePool,
        record_id: i32,
    ) -> Result<Vec<RecordHistory>, String> {
        let mut conn = pool.get_connection();

        if CommonService::get_record_by_id(&pool, record_id).is_err() {
            return Err("Record not found".to_string());
        }

        let record_histories = conn
            .exec_map(
                "SELECT * FROM record_history WHERE record_id = ?",
                (record_id,),
                |row: mysql::Row| RecordHistory::from_row(row),
            )
            .map_err(|e| format!("Failed to fetch record histories: {}", e))?;

        Ok(record_histories)
    }

    pub fn create_record_history(
        pool: &DatabasePool,
        record_id: i32,
        log: &str,
    ) -> Result<RecordHistory, String> {
        let mut conn = pool.get_connection();

        if CommonService::get_record_by_id(&pool, record_id).is_err() {
            return Err("Record not found".to_string());
        }

        let mut tx = conn
            .start_transaction(mysql::TxOpts::default())
            .map_err(|e| format!("Failed to start transaction: {}", e))?;

        tx.exec_drop(
            "INSERT INTO record_history (log, record_id) VALUES (?, ?)",
            (log, record_id),
        )
        .map_err(|e| format!("Failed to insert record history: {}", e))?;

        let last_insert_id = tx
            .last_insert_id()
            .ok_or_else(|| "Failed to get last insert id".to_string())?;

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        RecordHistoryService::get_record_history_by_id(&pool, last_insert_id as i32)
    }

    pub fn delete_record_history(
        pool: &DatabasePool,
        record_history_id: i32,
    ) -> Result<(), String> {
        let mut conn = pool.get_connection();

        if RecordHistoryService::get_record_history_by_id(&pool, record_history_id).is_err() {
            return Err("Record history not found".to_string());
        }

        conn.exec_drop(
            "DELETE FROM record_history WHERE id = ?",
            (record_history_id,),
        )
        .map_err(|e| format!("Failed to delete record history: {}", e))?;

        Ok(())
    }
}
