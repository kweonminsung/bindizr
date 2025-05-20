use crate::database::model::{record::Record, zone::Zone};
use crate::database::DatabasePool;
use crate::rndc::RNDC_CLIENT;
use mysql::prelude::*;

#[derive(Clone)]
pub struct ApiService;

impl ApiService {
    // pub fn get_table_names(pool: &DatabasePool) -> Vec<String> {
    //     let query = "SHOW TABLES";
    //     pool.get_connection()
    //         .query(query)
    //         .unwrap_or_else(|_| Vec::new())
    // }

    pub fn get_zones(pool: &DatabasePool) -> Vec<Zone> {
        let query = "SELECT * FROM zones";
        pool.get_connection()
            .query_map(query, |row: mysql::Row| Zone::from_row(row))
            .unwrap_or_else(|_| Vec::new())
    }

    pub fn get_zone(pool: &DatabasePool, zone_id: i32) -> Zone {
        let query = format!("SELECT * FROM zones WHERE id = {}", zone_id);
        pool.get_connection()
            .query_map(query, |row: mysql::Row| Zone::from_row(row))
            .unwrap_or_else(|_| Vec::new())
            .into_iter()
            .next()
            .expect("Zone not found")
    }

    pub fn get_records(pool: &DatabasePool, zone_id: Option<i32>) -> Vec<Record> {
        let query = match zone_id {
            Some(id) => format!("SELECT * FROM records WHERE zone_id = {}", id),
            None => "SELECT * FROM records".to_string(),
        };

        pool.get_connection()
            .query_map(query, |row: mysql::Row| Record::from_row(row))
            .unwrap_or_else(|_| Vec::new())
    }

    pub fn get_record(pool: &DatabasePool, record_id: i32) -> Record {
        let query = format!("SELECT * FROM records WHERE id = {}", record_id);
        pool.get_connection()
            .query_map(query, |row: mysql::Row| Record::from_row(row))
            .unwrap_or_else(|_| Vec::new())
            .into_iter()
            .next()
            .expect("Record not found")
    }

    pub fn create_record(pool: &DatabasePool, record: Record) -> Result<(), String> {
        // let query = format!(
        //     "INSERT INTO records (zone_id, name, type, content, ttl) VALUES ({}, '{}', '{}', '{}', {})",
        //     record.zone_id, record.name, record.type_, record.content, record.ttl
        // );

        // pool.get_connection()
        //     .query_drop(query)
        //     .map_err(|e| format!("Failed to create record: {}", e))

        Ok(())
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
