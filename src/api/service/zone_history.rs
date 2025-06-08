use super::common::CommonService;
use crate::{
    database::{model::zone_history::ZoneHistory, DatabasePool},
    log_error,
};
use mysql::prelude::Queryable;

#[derive(Clone)]
pub(crate) struct ZoneHistoryService;

impl ZoneHistoryService {
    fn get_zone_history_by_id(
        pool: &DatabasePool,
        zone_history_id: i32,
    ) -> Result<ZoneHistory, String> {
        let mut conn = pool.get_connection();

        let res = match conn.exec_map(
            r#"
                SELECT *
                FROM zone_history
                WHERE id = ?
            "#,
            (zone_history_id,),
            |row: mysql::Row| ZoneHistory::from_row(row),
        ) {
            Ok(zone_history) => zone_history,
            Err(e) => {
                log_error!("Failed to fetch zone history: {}", e);
                return Err("Failed to fetch zone history".to_string());
            }
        };

        res.into_iter()
            .next()
            .ok_or_else(|| "Zone history not found".to_string())
    }

    pub(crate) fn get_zone_histories(
        pool: &DatabasePool,
        zone_id: i32,
    ) -> Result<Vec<ZoneHistory>, String> {
        let mut conn = pool.get_connection();

        // Check if the zone exists
        CommonService::get_zone_by_id(&pool, zone_id)?;

        let res = match conn.exec_map(
            r#"
                SELECT *
                FROM zone_history
                WHERE zone_id = ?
            "#,
            (zone_id,),
            |row: mysql::Row| ZoneHistory::from_row(row),
        ) {
            Ok(zone_histories) => zone_histories,
            Err(e) => {
                log_error!("Failed to fetch zone histories: {}", e);
                return Err("Failed to fetch zone histories".to_string());
            }
        };

        Ok(res)
    }

    pub(crate) fn create_zone_history(
        tx: &mut mysql::Transaction,
        zone_id: i32,
        log: &str,
    ) -> Result<i32, String> {
        match tx.exec_drop(
            "INSERT INTO zone_history (zone_id, log) VALUES (?, ?)",
            (zone_id, log),
        ) {
            Ok(_) => {}
            Err(e) => {
                log_error!("Failed to insert zone history: {}", e);
                return Err("Failed to insert zone history".to_string());
            }
        };

        let last_inserted_id = match tx.last_insert_id() {
            Some(id) => id,
            None => {
                log_error!("Failed to get last inserted ID");
                return Err("Failed to insert zone history".to_string());
            }
        };

        Ok(last_inserted_id as i32)
    }

    pub(crate) fn delete_zone_history(
        pool: &DatabasePool,
        zone_history_id: i32,
    ) -> Result<(), String> {
        let mut conn = pool.get_connection();

        // Check if the zone history exists
        Self::get_zone_history_by_id(&pool, zone_history_id)?;

        match conn.exec_drop(
            r#"
            DELETE FROM zone_history
            WHERE id = ?
        "#,
            (zone_history_id,),
        ) {
            Ok(_) => {}
            Err(e) => {
                log_error!("Failed to delete zone history: {}", e);
                return Err("Failed to delete zone history".to_string());
            }
        };

        Ok(())
    }
}
