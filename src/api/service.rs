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

        dbg!(&result);

        for row in result {
            table_names.push(row);
        }

        table_names
    }
}
