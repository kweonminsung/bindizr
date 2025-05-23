use super::common::CommonService;
use crate::database::{model::zone_history::ZoneHistory, DatabasePool};
use mysql::prelude::Queryable;

#[derive(Clone)]
pub struct ZoneHistoryService;

impl ZoneHistoryService {
    fn get_zone_history_by_id(
        pool: &DatabasePool,
        zone_history_id: i32,
    ) -> Result<ZoneHistory, String> {
        let mut conn = pool.get_connection();

        let zone_history = conn
            .exec_first(
                r#"
                SELECT *
                FROM zone_history
                WHERE id = ?
            "#,
                (zone_history_id,),
            )
            .map_err(|e| format!("Failed to fetch zone history: {}", e))?
            .ok_or_else(|| "Zone history not found".to_string())?;

        Ok(ZoneHistory::from_row(zone_history))
    }

    pub fn get_zone_histories(
        pool: &DatabasePool,
        zone_id: i32,
    ) -> Result<Vec<ZoneHistory>, String> {
        let mut conn = pool.get_connection();

        if CommonService::get_zone_by_id(&pool, zone_id).is_err() {
            return Err("Zone not found".to_string());
        }

        let zone_histories = conn
            .exec_map(
                r#"
                SELECT *
                FROM zone_history
                WHERE zone_id = ?
            "#,
                (zone_id,),
                |row: mysql::Row| ZoneHistory::from_row(row),
            )
            .map_err(|e| format!("Failed to fetch zone histories: {}", e))?;

        Ok(zone_histories)
    }

    pub fn create_zone_history(
        tx: &mut mysql::Transaction,
        zone_id: i32,
        log: &str,
    ) -> Result<i32, String> {
        tx.exec_drop(
            "INSERT INTO zone_history (zone_id, log) VALUES (?, ?)",
            (zone_id, log),
        )
        .map_err(|e| format!("Failed to insert zone history: {}", e))?;

        let last_inserted_id = tx
            .last_insert_id()
            .ok_or_else(|| "Failed to get last inserted ID".to_string())?;

        Ok(last_inserted_id as i32)
    }

    pub fn delete_zone_history(pool: &DatabasePool, zone_history_id: i32) -> Result<(), String> {
        let mut conn = pool.get_connection();

        if Self::get_zone_history_by_id(&pool, zone_history_id).is_err() {
            return Err("Zone history not found".to_string());
        }

        conn.exec_drop(
            r#"
            DELETE FROM zone_history
            WHERE id = ?
        "#,
            (zone_history_id,),
        )
        .map_err(|e| format!("Failed to delete zone history: {}", e))?;

        Ok(())
    }
}
