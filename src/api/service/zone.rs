use super::{common::CommonService, zone_history::ZoneHistoryService};
use crate::{
    api::dto::CreateZoneRequest,
    database::{model::zone::Zone, DatabasePool},
};
use chrono::Utc;
use mysql::prelude::Queryable;

#[derive(Clone)]
pub(crate) struct ZoneService;

impl ZoneService {
    fn get_zone_by_name(pool: &DatabasePool, zone_name: &str) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

        let res = match conn.exec_map(
            r#"
                SELECT *
                FROM zones
                WHERE name = ?
            "#,
            (zone_name,),
            |row: mysql::Row| Zone::from_row(row),
        ) {
            Ok(zones) => zones,
            Err(e) => {
                eprintln!("Failed to fetch zone: {}", e);
                return Err("Failed to fetch zone".to_string());
            }
        };

        res.into_iter()
            .next()
            .ok_or_else(|| "Zone not found".to_string())
    }

    pub(crate) fn get_zones(pool: &DatabasePool) -> Result<Vec<Zone>, String> {
        let mut conn = pool.get_connection();

        match conn.exec_map(
            r#"
            SELECT *
            FROM zones
        "#,
            (),
            |row| Zone::from_row(row),
        ) {
            Ok(zones) => Ok(zones),
            Err(e) => {
                eprintln!("Failed to fetch zones: {}", e);
                Err("Failed to fetch zones".to_string())
            }
        }
    }

    pub(crate) fn get_zone(pool: &DatabasePool, zone_id: i32) -> Result<Zone, String> {
        CommonService::get_zone_by_id(&pool, zone_id)
    }

    pub(crate) fn create_zone(
        pool: &DatabasePool,
        create_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

        // Check if zone already exists
        if let Ok(_) = Self::get_zone_by_name(&pool, &create_zone_request.name) {
            return Err(format!("Zone {} already exists", create_zone_request.name));
        }

        let mut tx = match conn.start_transaction(mysql::TxOpts::default()) {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Failed to start transaction: {}", e);
                return Err("Failed to create zone".to_string());
            }
        };

        match tx.exec_drop(
            "INSERT INTO zones (name, primary_ns, primary_ns_ip, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                &create_zone_request.name,
                &create_zone_request.primary_ns,
                &create_zone_request.primary_ns_ip,
                &create_zone_request.admin_email,
                create_zone_request.ttl,
                create_zone_request.serial,
                create_zone_request.refresh.unwrap_or(86400),
                create_zone_request.retry.unwrap_or(7200),
                create_zone_request.expire.unwrap_or(3600000),
                create_zone_request.minimum_ttl.unwrap_or(86400),
            ),
        ) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to insert zone: {}", e);
                return Err("Failed to create zone".to_string());
            }
        };

        // Get last insert id
        let last_insert_id = match tx.last_insert_id() {
            Some(id) => id,
            None => {
                eprintln!("Failed to get last insert id");
                return Err("Failed to create zone".to_string());
            }
        };

        // Create zone history
        ZoneHistoryService::create_zone_history(
            &mut tx,
            last_insert_id as i32,
            &format!(
                "[{}] Zone created: id={}, name={}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                last_insert_id,
                create_zone_request.name,
            ),
        )?;

        match tx.commit() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to commit transaction: {}", e);
                return Err("Failed to create zone".to_string());
            }
        };

        CommonService::get_zone_by_id(&pool, last_insert_id as i32)
    }

    pub(crate) fn update_zone(
        pool: &DatabasePool,
        zone_id: i32,
        update_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

        // Check if zone exists
        CommonService::get_zone_by_id(&pool, zone_id)?;

        let mut tx = match conn.start_transaction(mysql::TxOpts::default()) {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Failed to start transaction: {}", e);
                return Err("Failed to update zone".to_string());
            }
        };

        match tx.exec_drop(
            "UPDATE zones SET name = ?, primary_ns = ?, primary_ns_ip = ?, admin_email = ?, ttl = ?, serial = ?, refresh = ?, retry = ?, expire = ?, minimum_ttl = ? WHERE id = ?",
            (
                &update_zone_request.name,
                &update_zone_request.primary_ns,
                &update_zone_request.primary_ns_ip,
                &update_zone_request.admin_email,
                update_zone_request.ttl,
                update_zone_request.serial,
                update_zone_request.refresh.unwrap_or(86400),
                update_zone_request.retry.unwrap_or(7200),
                update_zone_request.expire.unwrap_or(3600000),
                update_zone_request.minimum_ttl.unwrap_or(86400),
                zone_id,
            ),
        ) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to update zone: {}", e);
                return Err("Failed to update zone".to_string());
            }
        };

        // Create zone history
        ZoneHistoryService::create_zone_history(
            &mut tx,
            zone_id,
            &format!(
                "[{}] Zone updated: id={}, name={}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                zone_id,
                update_zone_request.name,
            ),
        )?;

        match tx.commit() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to commit transaction: {}", e);
                return Err("Failed to update zone".to_string());
            }
        };

        CommonService::get_zone_by_id(&pool, zone_id)
    }

    pub(crate) fn delete_zone(pool: &DatabasePool, zone_id: i32) -> Result<(), String> {
        let mut conn = pool.get_connection();

        // Check if zone exists
        CommonService::get_zone_by_id(&pool, zone_id)?;

        let mut tx = match conn.start_transaction(mysql::TxOpts::default()) {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Failed to start transaction: {}", e);
                return Err("Failed to delete zone".to_string());
            }
        };

        match tx.exec_drop("DELETE FROM zones WHERE id = ?", (zone_id,)) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to delete zone: {}", e);
                return Err("Failed to delete zone".to_string());
            }
        };

        // Create zone history
        ZoneHistoryService::create_zone_history(
            &mut tx,
            zone_id,
            &format!(
                "[{}] Zone deleted: id={}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                zone_id,
            ),
        )?;

        match tx.commit() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to commit transaction: {}", e);
                return Err("Failed to delete zone".to_string());
            }
        };

        Ok(())
    }
}
