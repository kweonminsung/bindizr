pub mod model;
mod utils;

use mysql::{prelude::Queryable, *};

#[derive(Clone)]
pub struct DatabasePool {
    pub pool: Pool,
}

impl DatabasePool {
    pub fn new(url: &String) -> Self {
        let opts = Opts::from_url(&url).expect("Invalid database URL");
        let pool = Pool::new(opts).expect("Failed to create database pool");
        let database_pool = DatabasePool { pool };

        Self::create_table(&database_pool);

        database_pool
    }

    pub fn create_table(pool: &DatabasePool) {
        let mut conn = pool.get_connection();

        conn.query_drop(
            r#"
            CREATE TABLE IF NOT EXISTS zones (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL,
                primary_ns VARCHAR(255) NOT NULL,
                admin_email VARCHAR(255) NOT NULL,
                ttl INT NOT NULL,
                serial INT NOT NULL,
                refresh INT NOT NULL DEFAULT 86400,
                retry INT NOT NULL DEFAULT 7200,
                expire INT NOT NULL DEFAULT 3600000,
                minimum_ttl INT NOT NULL DEFAULT 86400,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
        "#,
        )
        .unwrap();

        conn.query_drop(
            r#"
            CREATE TABLE IF NOT EXISTS records (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL,
                record_type VARCHAR(50) NOT NULL,
                value TEXT NOT NULL,
                ttl INT NOT NULL,
                priority INT,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                zone_id INT NOT NULL,
                FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
            );
        "#,
        )
        .unwrap();
    }

    pub fn get_connection(&self) -> PooledConn {
        self.pool
            .get_conn()
            .expect("Failed to get connection from pool")
    }
}
