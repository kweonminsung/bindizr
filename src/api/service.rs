use crate::database::DatabasePool;
use mysql::prelude::*;
use mysql::*;

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
        let result = self
            .pool
            .get_connection()
            .query_map(query, |row: Row| row.get::<String, usize>(0))
            .unwrap();

        for table_name in result {
            if let Some(name) = table_name {
                table_names.push(name);
            }
        }

        table_names
    }
}
