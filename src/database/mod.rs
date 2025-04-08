use crate::env::get_env;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::{sync::OnceLock, time::Duration};

pub enum DatabaseDriver {
    // Mysql,
    Sqlite,
}

impl DatabaseDriver {
    fn from_str(driver: &str) -> Result<Self, String> {
        match driver.to_lowercase().as_str() {
            // "mysql" => Ok(DatabaseDriver::Mysql),
            "sqlite" => Ok(DatabaseDriver::Sqlite),
            _ => Err(format!("Unsupported database driver: {}", driver)),
        }
    }
}

pub struct Session {
    pub driver: DatabaseDriver,
    pub connection: DatabaseConnection,
}

impl Session {
    pub async fn new() -> Self {
        let database_driver = get_env("DATABASE_DRIVER");

        match DatabaseDriver::from_str(&database_driver) {
            Ok(driver) => {
                match driver {
                    // DatabaseDriver::Mysql => {
                    //     println!("Initializing MySQL connection...");
                    //     // Add your MySQL initialization code here
                    // }
                    DatabaseDriver::Sqlite => {
                        let sqlite_path = get_env("SQLITE_PATH");

                        println!("Initializing SQLite connection...");

                        let mut opt = ConnectOptions::new(format!("sqlite://{}", sqlite_path));
                        opt.max_connections(100)
                            // .min_connections(5)
                            .connect_timeout(Duration::from_secs(8))
                            .acquire_timeout(Duration::from_secs(8))
                            .idle_timeout(Duration::from_secs(8))
                            // .max_lifetime(Duration::from_secs(8))
                            .sqlx_logging(true);

                        let connection = Database::connect(opt).await.unwrap();

                        Session { driver, connection }
                    }
                }
            }
            Err(err) => {
                panic!("{}", err);
            }
        }
    }
}

pub static SESSION: OnceLock<Session> = OnceLock::new();

pub async fn initialize() {
    let session = Session::new().await;
    match SESSION.set(session) {
        Ok(_) => (),
        Err(_) => {
            panic!("Failed to initialize database session.");
        }
    }
}
