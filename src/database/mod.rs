pub(crate) mod model;
mod schema;
mod utils;

use crate::{config, log_error, log_info};
use lazy_static::lazy_static;
use mysql::{prelude::Queryable, Error, Opts, Pool, PooledConn};

pub(crate) fn initialize() {
    // Test database connection
    match DATABASE_POOL.get_connection().query_drop("SELECT 1") {
        Ok(_) => {}
        Err(e) => {
            log_error!("Failed to connect to the database: {}", e);
            std::process::exit(1);
        }
    }
}

#[derive(Clone)]
pub(crate) struct DatabasePool {
    pool: Pool,
}

impl DatabasePool {
    pub(crate) fn new(url: &str) -> Self {
        let opts = Opts::from_url(url).unwrap_or_else(|_| {
            log_error!("Invalid database URL: {}", url);
            std::process::exit(1);
        });

        let pool = Pool::new(opts).unwrap_or_else(|e| {
            log_error!("Failed to create database pool: {}", e);
            std::process::exit(1);
        });
        let database_pool = DatabasePool { pool };

        // Create tables
        if let Err(e) = database_pool.create_tables() {
            log_error!("Failed to create tables: {}", e);
            std::process::exit(1);
        };

        log_info!("Database pool initialized");
        database_pool
    }

    fn create_tables(&self) -> Result<(), Error> {
        let mut conn = self.get_connection();

        // Get table creation queries from schema module
        for query in schema::get_table_creation_queries() {
            conn.query_drop(query)?;
        }
        Ok(())
    }

    pub(crate) fn get_connection(&self) -> PooledConn {
        self.pool
            .get_conn()
            .expect("Failed to get connection from pool")
    }
}

lazy_static! {
    pub(crate) static ref DATABASE_POOL: DatabasePool = {
        let database_url = config::get_config::<String>("mysql.mysql_server_url");
        DatabasePool::new(&database_url)
    };
}
