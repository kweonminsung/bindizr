#[cfg(test)]
mod tests;

use std::{env, fmt, net::IpAddr, path::PathBuf};

use config::{Config, File, FileFormat};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

/// Default path to the bindizr configuration file.
pub const BINDIZR_CONF_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

static BINDIZR_CONFIG: OnceCell<BindizrConfig> = OnceCell::new();

/// Top-level bindizr configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BindizrConfig {
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
}

/// HTTP API server settings.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiConfig {
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub require_authentication: bool,
    /// Serve Prometheus metrics at GET /metrics (unauthenticated, aggregate counts only).
    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,
    /// Register the `/external-dns` provider API endpoints. Which zones a
    /// caller may manage is decided by its API token's zone policies.
    #[serde(default)]
    pub external_dns_enabled: bool,
    /// Serve the OpenAPI document at GET /openapi.json and /openapi.yaml
    /// (unauthenticated). Off by default: it describes the whole API surface.
    #[serde(default)]
    pub openapi_enabled: bool,
}

fn default_metrics_enabled() -> bool {
    true
}

/// Database backend selection and per-backend connection settings.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(rename = "type")]
    pub database_type: DatabaseType,
    #[serde(default)]
    pub mysql: MysqlConfig,
    #[serde(default)]
    pub sqlite: SqliteConfig,
    #[serde(default)]
    pub postgresql: PostgresqlConfig,
}

/// Supported database backends.
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

impl std::str::FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mysql" => Ok(DatabaseType::Mysql),
            "sqlite" => Ok(DatabaseType::Sqlite),
            "postgresql" => Ok(DatabaseType::Postgresql),
            _ => Err("expected mysql, postgresql, or sqlite".to_string()),
        }
    }
}

/// MySQL connection settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MysqlConfig {
    pub server_url: String,
}

/// SQLite connection settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SqliteConfig {
    pub file_path: String,
}

/// PostgreSQL connection settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PostgresqlConfig {
    pub server_url: String,
}

/// DNS server and NOTIFY/nsupdate settings.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsConfig {
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub secondary_addrs: String,
    #[serde(default = "default_notify_after_update")]
    pub notify_after_update: bool,
    /// `sync` runs reload/NOTIFY inline; `async` hands it to a background worker.
    #[serde(default = "default_apply_mode")]
    pub apply_mode: ApplyMode,
    /// Window (ms) over which async-mode NOTIFYs are collapsed to one per zone.
    #[serde(default = "default_apply_batch_ms")]
    pub apply_batch_ms: u64,
    /// Cache each zone's records by serial so repeated AXFRs skip the DB read.
    #[serde(default = "default_zone_cache")]
    pub zone_cache: bool,
    #[serde(default)]
    pub notify_on_startup: bool,
    #[serde(default = "default_notify_retries")]
    pub notify_retries: u32,
    #[serde(default = "default_notify_timeout_secs")]
    pub notify_timeout_secs: u64,
    /// Accept unsigned nsupdate requests. Not recommended in production;
    /// signed requests are always verified.
    #[serde(default)]
    pub nsupdate_allow_unsigned: bool,
}

fn default_notify_after_update() -> bool {
    true
}

fn default_apply_mode() -> ApplyMode {
    ApplyMode::Sync
}

fn default_apply_batch_ms() -> u64 {
    50
}

fn default_zone_cache() -> bool {
    true
}

/// When zone reload/NOTIFY runs relative to the write request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplyMode {
    /// Inline: the write returns only after NOTIFY is sent.
    Sync,
    /// Queued to a background worker: the write returns at commit.
    Async,
}

impl fmt::Display for ApplyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            ApplyMode::Sync => "sync",
            ApplyMode::Async => "async",
        };
        write!(f, "{}", value)
    }
}

impl std::str::FromStr for ApplyMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sync" => Ok(ApplyMode::Sync),
            "async" => Ok(ApplyMode::Async),
            _ => Err("expected sync or async".to_string()),
        }
    }
}

fn default_notify_retries() -> u32 {
    3
}

fn default_notify_timeout_secs() -> u64 {
    5
}

/// Logging settings.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub log_level: LogLevel,
}

/// Console log verbosity levels.
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

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err("expected trace, debug, info, warn, or error".to_string()),
        }
    }
}

/// Load configuration from `conf_file_path` (or the default path / env var),
/// apply environment overrides, and store it as the global config.
pub fn initialize(conf_file_path: Option<&str>) -> Result<(), String> {
    let conf_file_path = resolve_config_path(conf_file_path);

    println!("Initializing configuration from file: {}", conf_file_path);

    let bindizr_config = load_config_file(&conf_file_path)?;
    BINDIZR_CONFIG.get_or_init(|| bindizr_config);

    Ok(())
}

/// Resolve the config file path: explicit argument, then `BINDIZR_CONFIG_PATH`,
/// then the default path.
pub fn resolve_config_path(conf_file_path: Option<&str>) -> String {
    resolve_config_path_with_env(conf_file_path, |name| env::var(name).ok())
}

fn resolve_config_path_with_env(
    conf_file_path: Option<&str>,
    get_env: impl Fn(&str) -> Option<String>,
) -> String {
    conf_file_path
        .map(str::to_string)
        .or_else(|| get_env("BINDIZR_CONFIG_PATH"))
        .unwrap_or_else(|| BINDIZR_CONF_PATH.to_string())
}

/// Load and validate `conf_file_path`, applying environment overrides, without
/// storing the result or exiting on failure.
pub fn load_config_file(conf_file_path: &str) -> Result<BindizrConfig, String> {
    if !PathBuf::from(conf_file_path).exists() {
        return Err(format!("Bindizr config does not exist: {}", conf_file_path));
    }

    let cfg = load_raw_config(conf_file_path)?;
    parse_bindizr_config(cfg)
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

fn parse_bindizr_config(cfg: Config) -> Result<BindizrConfig, String> {
    parse_bindizr_config_with_env(cfg, |name| env::var(name).ok())
}

fn parse_bindizr_config_with_env(
    cfg: Config,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<BindizrConfig, String> {
    let mut bindizr_config = cfg
        .try_deserialize::<BindizrConfig>()
        .map_err(|e| format!("Invalid Bindizr configuration: {}", e))?;

    apply_env_overrides_from(&mut bindizr_config, get_env)?;
    validate_database_config(&bindizr_config.database)?;
    validate_dns_config(&bindizr_config.dns)?;

    Ok(bindizr_config)
}

fn apply_env_overrides_from(
    config: &mut BindizrConfig,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<(), String> {
    if let Some(value) = get_env("BINDIZR_API_LISTEN_ADDR") {
        config.api.listen_addr = parse_env_value("BINDIZR_API_LISTEN_ADDR", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_API_PORT") {
        config.api.listen_port = parse_env_value("BINDIZR_API_PORT", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_API_REQUIRE_AUTHENTICATION") {
        config.api.require_authentication =
            parse_env_value("BINDIZR_API_REQUIRE_AUTHENTICATION", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_API_METRICS_ENABLED") {
        config.api.metrics_enabled = parse_env_value("BINDIZR_API_METRICS_ENABLED", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_API_EXTERNAL_DNS_ENABLED") {
        config.api.external_dns_enabled =
            parse_env_value("BINDIZR_API_EXTERNAL_DNS_ENABLED", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_API_OPENAPI_ENABLED") {
        config.api.openapi_enabled = parse_env_value("BINDIZR_API_OPENAPI_ENABLED", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_DATABASE_TYPE") {
        config.database.database_type = parse_env_value("BINDIZR_DATABASE_TYPE", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_MYSQL_SERVER_URL") {
        config.database.mysql.server_url = value;
    }
    if let Some(value) = get_env("BINDIZR_POSTGRESQL_SERVER_URL") {
        config.database.postgresql.server_url = value;
    }
    if let Some(value) = get_env("BINDIZR_SQLITE_FILE_PATH") {
        config.database.sqlite.file_path = value;
    }
    if let Some(value) = get_env("BINDIZR_DATABASE_URL") {
        match config.database.database_type {
            DatabaseType::Mysql => config.database.mysql.server_url = value,
            DatabaseType::Postgresql => config.database.postgresql.server_url = value,
            DatabaseType::Sqlite => {}
        }
    }
    if let Some(value) = get_env("BINDIZR_DNS_PORT") {
        config.dns.listen_port = parse_env_value("BINDIZR_DNS_PORT", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_DNS_LISTEN_ADDR") {
        config.dns.listen_addr = parse_env_value("BINDIZR_DNS_LISTEN_ADDR", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_SECONDARY_ADDRS") {
        config.dns.secondary_addrs = value;
    }
    if let Some(value) = get_env("BINDIZR_NSUPDATE_ALLOW_UNSIGNED") {
        config.dns.nsupdate_allow_unsigned =
            parse_env_value("BINDIZR_NSUPDATE_ALLOW_UNSIGNED", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_NOTIFY_AFTER_UPDATE") {
        config.dns.notify_after_update = parse_env_value("BINDIZR_NOTIFY_AFTER_UPDATE", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_APPLY_MODE") {
        config.dns.apply_mode = parse_env_value("BINDIZR_APPLY_MODE", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_APPLY_BATCH_MS") {
        config.dns.apply_batch_ms = parse_env_value("BINDIZR_APPLY_BATCH_MS", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_ZONE_CACHE") {
        config.dns.zone_cache = parse_env_value("BINDIZR_ZONE_CACHE", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_NOTIFY_ON_STARTUP") {
        config.dns.notify_on_startup = parse_env_value("BINDIZR_NOTIFY_ON_STARTUP", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_NOTIFY_RETRIES") {
        config.dns.notify_retries = parse_env_value("BINDIZR_NOTIFY_RETRIES", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_NOTIFY_TIMEOUT_SECS") {
        config.dns.notify_timeout_secs = parse_env_value("BINDIZR_NOTIFY_TIMEOUT_SECS", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_LOG_LEVEL") {
        config.logging.log_level = parse_env_value("BINDIZR_LOG_LEVEL", &value)?;
    }

    Ok(())
}

fn parse_env_value<T>(name: &str, value: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|e| format!("Invalid {} environment variable '{}': {}", name, value, e))
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

/// Reject separators-only `secondary_addrs` (e.g. ","), which would otherwise
/// read as "no secondaries configured".
fn validate_dns_config(config: &DnsConfig) -> Result<(), String> {
    let raw = &config.secondary_addrs;
    if !raw.trim().is_empty() && raw.split(',').all(|entry| entry.trim().is_empty()) {
        return Err(
            "dns.secondary_addrs contains no addresses; use \"\" when there are no secondaries"
                .to_string(),
        );
    }
    Ok(())
}

/// Return the global configuration; panics if [`initialize`] has not run.
pub fn get_bindizr_config() -> &'static BindizrConfig {
    BINDIZR_CONFIG.get().expect("Configuration not initialized")
}
