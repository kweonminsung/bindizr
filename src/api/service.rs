use crate::database::model::record::RecordType;
use crate::database::model::{record::Record, zone::Zone};
use crate::database::DatabasePool;
use crate::rndc::RNDC_CLIENT;
use mysql::prelude::*;

use super::dto::CreateRecordRequest;

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

    pub fn get_zones(pool: &DatabasePool) -> Vec<Zone> {
        let mut conn = pool.get_connection();

        conn.exec_map("SELECT * FROM zones", (), |row| Zone::from_row(row))
            .unwrap_or_else(|_| Vec::new())
    }

    pub fn get_zone(pool: &DatabasePool, zone_id: i32) -> Result<Zone, String> {
        ApiService::get_zone_by_id(&pool, zone_id)
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

    pub fn get_record(pool: &DatabasePool, record_id: i32) -> Record {
        let mut conn = pool.get_connection();

        conn.exec_map(
            "SELECT * FROM records WHERE id = ?",
            (record_id,),
            |row: mysql::Row| Record::from_row(row),
        )
        .unwrap_or_else(|_| Vec::new())
        .into_iter()
        .next()
        .expect("Record not found")
    }

    pub fn create_record(
        pool: &DatabasePool,
        create_record_request: &CreateRecordRequest,
    ) -> Result<Record, String> {
        let mut conn = pool.get_connection();

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

        conn.exec_map(
            "SELECT * FROM records WHERE id = ?",
            (last_insert_id,),
            |row: mysql::Row| Record::from_row(row),
        )
        .map_err(|e| format!("Failed to fetch created record: {}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| "Created record not found".to_string())
    }

    pub fn get_dns_status() -> String {
        let rndc_client = &RNDC_CLIENT;

        let res = rndc_client.rndc_command("status").unwrap();

        if !res.result {
            println!("Error: {}", res.err.unwrap_or_default());
        }

        res.text.unwrap()
    }
}
