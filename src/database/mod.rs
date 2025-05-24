pub mod model;
mod utils;
mod schema;

use crate::config;
use lazy_static::lazy_static;
use mysql::{prelude::Queryable, Opts, Pool, PooledConn};
use std::time::Duration;

pub fn initialize() {
    // Test database connection
    match DATABASE_POOL.get_connection().query_drop("SELECT 1") {
        Ok(_) => println!("Database initialized"),
        Err(e) => eprintln!("Failed to connect to the database: {}", e),
    }
}

#[derive(Clone)]
pub struct DatabasePool {
    pool: Pool,
}

impl DatabasePool {
    pub fn new(url: &str) -> Self {
        // Optimize connection pool options
        let mut opts = Opts::from_url(url).expect("Invalid database URL");
        opts.pool_opts.min_connections = 5;
        opts.pool_opts.max_connections = 20;
        opts.pool_opts.idle_timeout = Some(Duration::from_secs(300));
        opts.pool_opts.constraints.max_lifetime = Some(Duration::from_secs(3600));
        
        let pool = Pool::new(opts).expect("Failed to create database pool");
        let database_pool = DatabasePool { pool };

        // Create tables
        database_pool.create_tables();

        database_pool
    }

    fn create_tables(&self) {
        let mut conn = self.get_connection();
        
        // Get table creation queries from schema module
        for query in schema::get_table_creation_queries() {
            if let Err(e) = conn.query_drop(query) {
                eprintln!("Error creating table: {}", e);
            }
        }
    }

    pub fn get_connection(&self) -> PooledConn {
        self.pool
            .get_conn()
            .expect("Failed to get connection from pool")
    }
}

lazy_static! {
    pub static ref DATABASE_POOL: DatabasePool = {
        let database_url = config::get_config("mysql.server_url");
        DatabasePool::new(&database_url)
    };
}