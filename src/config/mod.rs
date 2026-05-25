#[cfg(test)]
mod tests;

pub mod error;

use config::{Config, File, FileFormat};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, path::PathBuf};

// Config file path
#[allow(dead_code)]
pub const BINDIZR_CONF_DIR: &str = "/etc/bindizr";
pub const BINDIZR_CONF_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

static CONFIG: OnceCell<Config> = OnceCell::new();
static BINDIZR_CONFIG: OnceCell<BindizrConfig> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BindizrConfig {
    pub listen_addr: IpAddr,
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiConfig {
    #[serde(alias = "port")]
    pub listen_port: u16,
    pub require_authentication: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(rename = "type")]
    pub database_type: DatabaseType,
    pub mysql: MysqlConfig,
    pub sqlite: SqliteConfig,
    #[serde(alias = "postgres")]
    pub postgresql: PostgresqlConfig,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    Mysql,
    Sqlite,
    Postgresql,
}

impl fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            DatabaseType::Mysql => "mysql",
            DatabaseType::Sqlite => "sqlite",
            DatabaseType::Postgresql => "postgresql",
        };
        write!(f, "{}", value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MysqlConfig {
    pub server_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SqliteConfig {
    pub file_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PostgresqlConfig {
    pub server_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsConfig {
    pub listen_port: u16,
    pub secondary_addrs: String,
    /// Empty disables nsupdate TSIG authentication.
    #[serde(default)]
    pub nsupdate_tsig_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub log_level: LogLevel,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        };
        write!(f, "{}", value)
    }
}

pub fn initialize(conf_file_path: Option<&str>) {
    let conf_file_path = conf_file_path.unwrap_or(BINDIZR_CONF_PATH);

    if !PathBuf::from(conf_file_path).exists() {
        exit_config_error(format!("Bindizr config does not exist: {}", conf_file_path));
    }

    println!("Initializing configuration from file: {}", conf_file_path);

    let cfg = load_raw_config(conf_file_path).unwrap_or_else(|err| exit_config_error(err));
    let bindizr_config = parse_bindizr_config(&cfg).unwrap_or_else(|err| exit_config_error(err));

    CONFIG.get_or_init(|| cfg);
    BINDIZR_CONFIG.get_or_init(|| bindizr_config);
}

fn load_raw_config(conf_file_path: &str) -> Result<Config, String> {
    Config::builder()
        .add_source(File::new(conf_file_path, FileFormat::Toml).required(true))
        .build()
        .map_err(|e| {
            format!(
                "Failed to build configuration from file '{}': {}",
                conf_file_path, e
            )
        })
}

fn parse_bindizr_config(cfg: &Config) -> Result<BindizrConfig, String> {
    let bindizr_config = cfg
        .clone()
        .try_deserialize::<BindizrConfig>()
        .map_err(|e| format!("Invalid Bindizr configuration: {}", e))?;

    validate_database_config(&bindizr_config.database)?;

    Ok(bindizr_config)
}

fn validate_database_config(config: &DatabaseConfig) -> Result<(), String> {
    match config.database_type {
        DatabaseType::Mysql if config.mysql.server_url.trim().is_empty() => Err(
            "database.mysql.server_url must not be empty when database.type is mysql".to_string(),
        ),
        DatabaseType::Postgresql if config.postgresql.server_url.trim().is_empty() => Err(
            "database.postgresql.server_url must not be empty when database.type is postgresql"
                .to_string(),
        ),
        DatabaseType::Sqlite if config.sqlite.file_path.trim().is_empty() => Err(
            "database.sqlite.file_path must not be empty when database.type is sqlite".to_string(),
        ),
        _ => Ok(()),
    }
}

fn exit_config_error(message: String) -> ! {
    eprintln!("{}", message);
    std::process::exit(1);
}

#[allow(dead_code)]
pub fn get_bindizr_config() -> &'static BindizrConfig {
    BINDIZR_CONFIG.get().expect("Configuration not initialized")
}
