use crate::database::model::zone::Zone;
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
        let mut table_names = Vec::new();

        let query = "SHOW TABLES";
        let result: Vec<String> = self.pool.get_connection().query(query).unwrap();

        // dbg!(&result);

        for row in result {
            table_names.push(row);
        }

        table_names
    }

    pub fn get_zones(&self) -> Vec<Zone> {
        let mut zones = Vec::new();

        let query = "SELECT * FROM zones";
        let result: Vec<Zone> = self
            .pool
            .get_connection()
            .query_map(query, |row: mysql::Row| Zone::from_row(row))
            .unwrap();

        // dbg!(&result);

        for row in result {
            zones.push(row);
        }

        zones
    }

    pub fn get_zone(&self, zone_id: i32) -> Zone {
        let query = format!("SELECT * FROM zones WHERE id = {}", zone_id);
        let result: Vec<Zone> = self
            .pool
            .get_connection()
            .query_map(query, |row: mysql::Row| Zone::from_row(row))
            .unwrap();

        // dbg!(&result);

        result[0].clone()
    }
}
