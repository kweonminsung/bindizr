use crate::env::get_env;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::time::Duration;

enum DatabaseDriver {
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
    driver: DatabaseDriver,
    pub connection: DatabaseConnection,
}

impl Session {
    pub async fn new() -> Result<Self, String> {
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

                        let connection = match Database::connect(opt).await {
                            Ok(conn) => conn,
                            Err(err) => {
                                return Err(format!(
                                    "Failed to connect to SQLite database: {}",
                                    err
                                ))
                            }
                        };

                        Ok(Session {
                            driver: DatabaseDriver::Sqlite,
                            connection,
                        })
                    }
                }
            }
            Err(err) => Err(err),
        }
    }
}
