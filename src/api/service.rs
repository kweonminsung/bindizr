use crate::database::model::{record::Record, zone::Zone};
use crate::database::DatabasePool;
use lazy_static::lazy_static;
use mysql::prelude::*;

#[derive(Clone)]
pub struct ApiService;

impl ApiService {
    pub fn get_table_names(pool: &DatabasePool) -> Vec<String> {
        let query = "SHOW TABLES";
        pool.get_connection()
            .query(query)
            .unwrap_or_else(|_| Vec::new())
    }

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
}

lazy_static! {
    pub static ref DATABASE_POOL: DatabasePool = {
        let database_url = crate::env::get_env("DATABASE_URL");
        DatabasePool::new(&database_url)
    };
}
