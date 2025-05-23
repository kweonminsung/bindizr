use super::{common::CommonService, zone_history::ZoneHistoryService};
use crate::{
    api::dto::CreateZoneRequest,
    database::{model::zone::Zone, DatabasePool},
};
use chrono::Utc;
use mysql::prelude::Queryable;

#[derive(Clone)]
pub struct ZoneService;

impl ZoneService {
    fn get_zone_by_name(pool: &DatabasePool, zone_name: &str) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

        let zone = conn
            .exec_first(
                r#"
                SELECT *
                FROM zones
                WHERE name = ?
            "#,
                (zone_name,),
            )
            .map_err(|e| format!("Failed to fetch zone: {}", e))?
            .ok_or_else(|| "Zone not found".to_string())?;

        Ok(Zone::from_row(zone))
    }

    pub fn get_zones(pool: &DatabasePool) -> Vec<Zone> {
        let mut conn = pool.get_connection();

        conn.exec_map(
            r#"
            SELECT *
            FROM zones
        "#,
            (),
            |row| Zone::from_row(row),
        )
        .unwrap_or_else(|_| Vec::new())
    }

    pub fn get_zone(pool: &DatabasePool, zone_id: i32) -> Result<Zone, String> {
        CommonService::get_zone_by_id(&pool, zone_id)
    }

    pub fn create_zone(
        pool: &DatabasePool,
        create_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

        // check if zone already exists
        if let Ok(_) = Self::get_zone_by_name(&pool, &create_zone_request.name) {
            return Err(format!("Zone {} already exists", create_zone_request.name));
        }

        let mut tx = conn
            .start_transaction(mysql::TxOpts::default())
            .map_err(|e| format!("Failed to start transaction: {}", e))?;

        tx.exec_drop(
            "INSERT INTO zones (name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                &create_zone_request.name,
                &create_zone_request.primary_ns,
                &create_zone_request.admin_email,
                create_zone_request.ttl,
                create_zone_request.serial,
                create_zone_request.refresh.unwrap_or(86400),
                create_zone_request.retry.unwrap_or(7200),
                create_zone_request.expire.unwrap_or(3600000),
                create_zone_request.minimum_ttl.unwrap_or(86400),
            ),
        )
        .map_err(|e| format!("Failed to insert zone: {}", e))?;

        // Get last insert id
        let last_insert_id = tx
            .last_insert_id()
            .ok_or_else(|| "Failed to get last insert id".to_string())?;

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        // create zone history
        ZoneHistoryService::create_zone_history(
            pool,
            last_insert_id as i32,
            &format!(
                "[{}] Zone created: id={}, name={}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                last_insert_id,
                create_zone_request.name,
            ),
        )?;

        CommonService::get_zone_by_id(&pool, last_insert_id as i32)
    }

    pub fn update_zone(
        pool: &DatabasePool,
        zone_id: i32,
        update_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

        if CommonService::get_zone_by_id(&pool, zone_id).is_err() {
            return Err("Zone not found".to_string());
        }

        let mut tx = conn
            .start_transaction(mysql::TxOpts::default())
            .map_err(|e| format!("Failed to start transaction: {}", e))?;

        tx.exec_drop(
            "UPDATE zones SET name = ?, primary_ns = ?, admin_email = ?, ttl = ?, serial = ?, refresh = ?, retry = ?, expire = ?, minimum_ttl = ? WHERE id = ?",
            (
                &update_zone_request.name,
                &update_zone_request.primary_ns,
                &update_zone_request.admin_email,
                update_zone_request.ttl,
                update_zone_request.serial,
                update_zone_request.refresh.unwrap_or(86400),
                update_zone_request.retry.unwrap_or(7200),
                update_zone_request.expire.unwrap_or(3600000),
                update_zone_request.minimum_ttl.unwrap_or(86400),
                zone_id,
            ),
        )
        .map_err(|e| format!("Failed to update zone: {}", e))?;

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        // create zone history
        ZoneHistoryService::create_zone_history(
            pool,
            zone_id,
            &format!(
                "[{}] Zone updated: id={}, name={}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                zone_id,
                update_zone_request.name,
            ),
        )?;

        CommonService::get_zone_by_id(&pool, zone_id)
    }

    pub fn delete_zone(pool: &DatabasePool, zone_id: i32) -> Result<(), String> {
        let mut conn = pool.get_connection();

        if CommonService::get_zone_by_id(&pool, zone_id).is_err() {
            return Err("Zone not found".to_string());
        }

        let mut tx = conn
            .start_transaction(mysql::TxOpts::default())
            .map_err(|e| format!("Failed to start transaction: {}", e))?;

        tx.exec_drop("DELETE FROM zones WHERE id = ?", (zone_id,))
            .map_err(|e| format!("Failed to delete zone: {}", e))?;

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        // create zone history
        ZoneHistoryService::create_zone_history(
            pool,
            zone_id,
            &format!(
                "[{}] Zone deleted: id={}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                zone_id,
            ),
        )?;

        Ok(())
    }
}
