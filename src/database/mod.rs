use crate::env::get_env;
use sqlx::{Connection, MySqlPool, SqliteConnection};

enum DatabaseDriver {
    Mysql,
    Sqlite,
}

impl DatabaseDriver {
    fn from_str(driver: &str) -> Result<Self, String> {
        match driver.to_lowercase().as_str() {
            "mysql" => Ok(DatabaseDriver::Mysql),
            "sqlite" => Ok(DatabaseDriver::Sqlite),
            _ => Err(format!("Unsupported database driver: {}", driver)),
        }
    }
}

#[tokio::main]
pub async fn initialize() -> Result<(), String> {
    let database_driver = get_env("DATABASE_DRIVER");
    let database_url = get_env("DATABASE_URL");

    match DatabaseDriver::from_str(&database_driver) {
        Ok(driver) => {
            match driver {
                DatabaseDriver::Mysql => {
                    println!("Initializing MySQL connection...");
                    // Add your MySQL initialization code here
                }
                DatabaseDriver::Sqlite => {
                    println!("Initializing SQLite connection...");

                    // Check if the SQLite database file exists
                    let database_path = std::path::Path::new(&database_url);
                    if !database_path.exists() {
                        std::fs::create_dir_all(database_path.parent().unwrap()).map_err(|e| {
                            format!("Failed to create directory for SQLite database: {}", e)
                        })?;
                        std::fs::File::create(database_path)
                            .map_err(|e| format!("Failed to create SQLite database file: {}", e))?;
                    }

                    // Initialize SQLite connection
                    let mut conn = SqliteConnection::connect(&database_url)
                        .await
                        .map_err(|e| format!("Failed to connect to SQLite: {}", e))?;

                    // Create the database schema if it doesn't exist
                    sqlx::query(
                        r#"
                        CREATE TABLE IF NOT EXISTS dns_records (
                            `id`            int(11) NOT NULL auto_increment,
                            `zone`          varchar(64) default NULL,
                            `host`          varchar(64) default NULL,
                            `type`          varchar(8) default NULL,
                            `data`          varchar(64) default NULL,
                            `ttl`           int(11) NOT NULL default '3600',
                            `mx_priority`   int(11) default NULL,
                            `refresh`       int(11) NOT NULL default '3600',
                            `retry`         int(11) NOT NULL default '3600',
                            `expire`        int(11) NOT NULL default '86400',
                            `minimum`       int(11) NOT NULL default '3600',
                            `serial`        bigint(20) NOT NULL default '2008082700',
                            `resp_person`   varchar(64) NOT NULL default 'resp.person.email',
                            `primary_ns`    varchar(64) NOT NULL default 'ns1.yourdns.here',
                            `data_count`    int(11) NOT NULL default '0',
                            `created_at`    datetime NOT NULL default '0000-00-00 00:00:00',
                            `updated_at`    datetime NOT NULL default '0000-00-00 00:00:00',
                            PRIMARY KEY (`id`), KEY `host` (`host`), KEY `zone` (`zone`), KEY `type` (`type`)
                        );
                        "#,
                    )
                    .execute(&mut conn)
                    .await
                    .map_err(|e| format!("Failed to create dns_records table: {}", e))?;
                }
            }
            Ok(())
        }
        Err(err) => Err(err),
    }
}
