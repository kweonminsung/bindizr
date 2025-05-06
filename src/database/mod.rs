mod model;

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
            CREATE TABLE IF NOT EXISTS records (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL,
                record_type VARCHAR(50) NOT NULL,
                value TEXT NOT NULL,
                ttl INT NOT NULL,
                priority INT,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            );
        "#,
        )
        .unwrap();

        conn.query_drop(
            r#"
            CREATE TABLE IF NOT EXISTS zones (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) NOT NULL,
                admin_email VARCHAR(255) NOT NULL,
                ttl INT NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
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
