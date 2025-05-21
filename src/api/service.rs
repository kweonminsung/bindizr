use crate::database::model::record::RecordType;
use crate::database::model::{record::Record, zone::Zone};
use crate::database::DatabasePool;
use crate::rndc::RNDC_CLIENT;
use mysql::prelude::*;

use super::dto::{CreateRecordRequest, CreateZoneRequest};

#[derive(Clone)]
pub struct ApiService;

impl ApiService {
    // pub fn get_table_names(pool: &DatabasePool) -> Vec<String> {
    //     let query = "SHOW TABLES";
    //     pool.get_connection()
    //         .query(query)
    //         .unwrap_or_else(|_| Vec::new())
    // }

    fn get_zone_by_id(pool: &DatabasePool, zone_id: i32) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

        conn.exec_map(
            "SELECT * FROM zones WHERE id = ?",
            (zone_id,),
            |row: mysql::Row| Zone::from_row(row),
        )
        .map_err(|e| format!("Failed to fetch zone: {}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| "Zone not found".to_string())
    }

    fn get_record_by_id(pool: &DatabasePool, record_id: i32) -> Result<Record, String> {
        let mut conn = pool.get_connection();

        conn.exec_map(
            "SELECT * FROM records WHERE id = ?",
            (record_id,),
            |row: mysql::Row| Record::from_row(row),
        )
        .map_err(|e| format!("Failed to fetch record: {}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| "Record not found".to_string())
    }

    pub fn get_zones(pool: &DatabasePool) -> Vec<Zone> {
        let mut conn = pool.get_connection();

        conn.exec_map("SELECT * FROM zones", (), |row| Zone::from_row(row))
            .unwrap_or_else(|_| Vec::new())
    }

    pub fn get_zone(pool: &DatabasePool, zone_id: i32) -> Result<Zone, String> {
        ApiService::get_zone_by_id(&pool, zone_id)
    }

    pub fn create_zone(
        pool: &DatabasePool,
        create_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

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

        ApiService::get_zone_by_id(&pool, last_insert_id as i32)
    }

    pub fn get_records(pool: &DatabasePool, zone_id: Option<i32>) -> Vec<Record> {
        let mut conn = pool.get_connection();

        match zone_id {
            Some(id) => conn
                .exec_map(
                    "SELECT * FROM records WHERE zone_id = ?",
                    (id,),
                    |row: mysql::Row| Record::from_row(row),
                )
                .unwrap_or_else(|_| Vec::new()),
            None => conn
                .exec_map("SELECT * FROM records", (), |row: mysql::Row| {
                    Record::from_row(row)
                })
                .unwrap_or_else(|_| Vec::new()),
        }
    }

    pub fn get_record(pool: &DatabasePool, record_id: i32) -> Result<Record, String> {
        ApiService::get_record_by_id(&pool, record_id)
    }

    pub fn create_record(
        pool: &DatabasePool,
        create_record_request: &CreateRecordRequest,
    ) -> Result<Record, String> {
        let mut conn = pool.get_connection();

        if ApiService::get_zone_by_id(&pool, create_record_request.zone_id).is_err() {
            return Err("Zone not found".to_string());
        }

        let record_type = RecordType::from_str(&create_record_request.record_type)
            .map_err(|_| format!("Invalid record type: {}", create_record_request.record_type))?;

        let mut tx = conn
            .start_transaction(mysql::TxOpts::default())
            .map_err(|e| format!("Failed to start transaction: {}", e))?;

        tx.exec_drop(
            "INSERT INTO records (name, record_type, value, ttl, priority, zone_id) VALUES (?, ?, ?, ?, ?, ?)",
            (
                &create_record_request.name,
                record_type.to_str(),
                &create_record_request.value,
                create_record_request.ttl,
                create_record_request.priority,
                create_record_request.zone_id,
            ),
        )
        .map_err(|e| format!("Failed to insert record: {}", e))?;

        // Get last insert id
        let last_insert_id = tx
            .last_insert_id()
            .ok_or_else(|| "Failed to get last insert id".to_string())?;

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        ApiService::get_record_by_id(&pool, last_insert_id as i32)
    }

    pub fn get_dns_status() -> Result<String, String> {
        let rndc_client = &RNDC_CLIENT;

        let res = rndc_client.rndc_command("status")?;

        if !res.result {
            return Err("Failed to get DNS status".to_string());
        }

        match res.text {
            Some(text) => Ok(text),
            None => Ok("".to_string()),
        }
    }
}
