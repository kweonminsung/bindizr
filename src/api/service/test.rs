use crate::database::DatabasePool;
use mysql::prelude::Queryable;

#[derive(Clone)]
pub struct TestService;

impl TestService {
    pub fn get_table_names(pool: &DatabasePool) -> Vec<String> {
        let mut conn = pool.get_connection();

        let query = "SHOW TABLES";

        match conn.query_map(query, |table_name: String| table_name) {
            Ok(table_names) => table_names,
            Err(e) => {
                log_error!("Failed to fetch table names: {}", e);
                Vec::new()
            }
        }
    }
}
