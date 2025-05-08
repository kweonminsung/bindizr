use crate::database::model::{record::Record, zone::Zone};
use crate::database::DatabasePool;
use mysql::prelude::*;

#[derive(Clone)]
pub struct ApiService {
    pub pool: DatabasePool,
}

impl ApiService {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    pub fn get_table_names(&self) -> Vec<String> {
        let query = "SHOW TABLES";
        self.pool
            .get_connection()
            .query(query)
            .unwrap_or_else(|_| Vec::new())
    }

    pub fn get_zones(&self) -> Vec<Zone> {
        let query = "SELECT * FROM zones";
        self.pool
            .get_connection()
            .query_map(query, |row: mysql::Row| Zone::from_row(row))
            .unwrap_or_else(|_| Vec::new())
    }

    pub fn get_zone(&self, zone_id: i32) -> Zone {
        let query = format!("SELECT * FROM zones WHERE id = {}", zone_id);
        self.pool
            .get_connection()
            .query_map(query, |row: mysql::Row| Zone::from_row(row))
            .unwrap_or_else(|_| Vec::new())
            .into_iter()
            .next()
            .expect("Zone not found")
    }

    pub fn get_records(&self, zone_id: Option<i32>) -> Vec<Record> {
        let query = match zone_id {
            Some(id) => format!("SELECT * FROM records WHERE zone_id = {}", id),
            None => "SELECT * FROM records".to_string(),
        };

        self.pool
            .get_connection()
            .query_map(query, |row: mysql::Row| Record::from_row(row))
            .unwrap_or_else(|_| Vec::new())
    }

    pub fn get_record(&self, record_id: i32) -> Record {
        let query = format!("SELECT * FROM records WHERE id = {}", record_id);
        self.pool
            .get_connection()
            .query_map(query, |row: mysql::Row| Record::from_row(row))
            .unwrap_or_else(|_| Vec::new())
            .into_iter()
            .next()
            .expect("Record not found")
    }
}
