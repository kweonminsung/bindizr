use mysql::*;
// use std::sync::OnceLock;

#[derive(Clone)]
pub struct DatabasePool {
    pub pool: Pool,
}

impl DatabasePool {
    pub fn new(url: &String) -> Self {
        let opts = Opts::from_url(&url).expect("Invalid database URL");

        let pool = Pool::new(opts).expect("Failed to create database pool");

        DatabasePool { pool }
    }

    pub fn get_connection(&self) -> PooledConn {
        self.pool
            .get_conn()
            .expect("Failed to get connection from pool")
    }
}

// pub static DATABASE_POOL: OnceLock<DatabasePool> = OnceLock::new();

// pub fn initialize() {
//     let database_pool = DatabasePool::new();

//     match DATABASE_POOL.set(database_pool) {
//         Ok(_) => (),
//         Err(_) => {
//             panic!("Failed to initialize database pool.");
//         }
//     }
// }
