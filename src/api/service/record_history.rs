use super::common::CommonService;
use crate::database::{model::record_history::RecordHistory, DatabasePool};
use mysql::prelude::Queryable;

#[derive(Clone)]
pub(crate) struct RecordHistoryService;

impl RecordHistoryService {
    fn get_record_history_by_id(
        pool: &DatabasePool,
        record_history_id: i32,
    ) -> Result<RecordHistory, String> {
        let mut conn = pool.get_connection();

        let res = match conn.exec_map(
            r#"
                SELECT *
                FROM record_history
                WHERE id = ?
            "#,
            (record_history_id,),
            |row: mysql::Row| RecordHistory::from_row(row),
        ) {
            Ok(record_history) => record_history,
            Err(e) => {
                eprintln!("Failed to fetch record history: {}", e);
                return Err("Failed to fetch record history".to_string());
            }
        };

        res.into_iter()
            .next()
            .ok_or_else(|| "Record history not found".to_string())
    }

    pub(crate) fn get_record_histories(
        pool: &DatabasePool,
        record_id: i32,
    ) -> Result<Vec<RecordHistory>, String> {
        let mut conn = pool.get_connection();

        // Check if the record exists
        CommonService::get_record_by_id(&pool, record_id)?;

        let res = match conn.exec_map(
            r#"
                SELECT *
                FROM record_history
                WHERE record_id = ?
            "#,
            (record_id,),
            |row: mysql::Row| RecordHistory::from_row(row),
        ) {
            Ok(record_histories) => record_histories,
            Err(e) => {
                eprintln!("Failed to fetch record histories: {}", e);
                return Err("Failed to fetch record histories".to_string());
            }
        };

        Ok(res)
    }

    pub(crate) fn create_record_history(
        tx: &mut mysql::Transaction,
        record_id: i32,
        log: &str,
    ) -> Result<i32, String> {
        match tx.exec_drop(
            "INSERT INTO record_history (log, record_id) VALUES (?, ?)",
            (log, record_id),
        ) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to insert record history: {}", e);
                return Err("Failed to insert record history".to_string());
            }
        };

        let last_insert_id = match tx.last_insert_id() {
            Some(id) => id,
            None => {
                eprintln!("Failed to get last insert id");
                return Err("Failed to insert record history".to_string());
            }
        };

        Ok(last_insert_id as i32)
    }

    pub(crate) fn delete_record_history(
        pool: &DatabasePool,
        record_history_id: i32,
    ) -> Result<(), String> {
        let mut conn = pool.get_connection();

        // Check if the record history exists
        Self::get_record_history_by_id(&pool, record_history_id)?;

        match conn.exec_drop(
            "DELETE FROM record_history WHERE id = ?",
            (record_history_id,),
        ) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to delete record history: {}", e);
                return Err("Failed to delete record history".to_string());
            }
        };

        Ok(())
    }
}
