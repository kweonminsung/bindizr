#[cfg(test)]
mod tests;

use std::{env, fmt, net::IpAddr, path::PathBuf};

use config::{Config, File, FileFormat};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

use crate::dns::address::is_address_target;

pub(crate) const BINDIZR_CONF_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

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
    /// caller may manage is decided by its API token's grants.
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
    /// `sync` sends NOTIFY inline; `async` hands it to a background worker.
    #[serde(default = "default_notify_mode")]
    pub notify_mode: NotifyMode,
    /// Window (ms) over which async-mode NOTIFYs are collapsed to one per zone.
    #[serde(default = "default_notify_batch_ms")]
    pub notify_batch_ms: u64,
    /// Cache each zone's records by serial so repeated AXFRs skip the DB read.
    #[serde(default = "default_zone_cache")]
    pub zone_cache: bool,
    /// Megabytes of record data the zone cache may hold before evicting the
    /// least recently used zone. A zone larger than this is served uncached.
    #[serde(default = "default_zone_cache_max_mb")]
    pub zone_cache_max_mb: u64,
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
    /// Days of IXFR journal and SOA history to keep (0 = unlimited). Requests
    /// for pruned serials fall back to AXFR; rollback reaches only kept serials.
    #[serde(default = "default_journal_retention_days")]
    pub journal_retention_days: u32,
}

fn default_journal_retention_days() -> u32 {
    365
}

fn default_notify_after_update() -> bool {
    true
}

fn default_notify_mode() -> NotifyMode {
    NotifyMode::Sync
}

fn default_notify_batch_ms() -> u64 {
    50
}

fn default_zone_cache() -> bool {
    true
}

fn default_zone_cache_max_mb() -> u64 {
    64
}

/// When NOTIFY dispatch runs relative to the write request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyMode {
    /// Inline: the write returns only after NOTIFY is sent.
    Sync,
    /// Queued to a background worker: the write returns at commit.
    Async,
}

impl fmt::Display for NotifyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            NotifyMode::Sync => "sync",
            NotifyMode::Async => "async",
        };
        write!(f, "{}", value)
    }
}

impl std::str::FromStr for NotifyMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sync" => Ok(NotifyMode::Sync),
            "async" => Ok(NotifyMode::Async),
            _ => Err("expected sync or async".to_string()),
        }
    }
}

fn default_notify_retries() -> u32 {
    3
}

fn default_notify_timeout_secs() -> u64 {
    3
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

    // Predates the logger, which is installed from the config this loads.
    eprintln!("Initializing configuration from file: {}", conf_file_path);

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
    BindizrConfig::from_raw(cfg, |name| env::var(name).ok())
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

impl BindizrConfig {
    fn from_raw(raw: Config, get_env: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut bindizr_config = raw
            .try_deserialize::<Self>()
            .map_err(|e| format!("Invalid Bindizr configuration: {}", e))?;

        bindizr_config.apply_env_overrides(get_env)?;
        bindizr_config.api.validate()?;
        bindizr_config.database.validate()?;
        bindizr_config.dns.validate()?;
        bindizr_config.validate_listeners()?;

        Ok(bindizr_config)
    }

    fn apply_env_overrides(
        &mut self,
        get_env: impl Fn(&str) -> Option<String>,
    ) -> Result<(), String> {
        if let Some(value) = get_env("BINDIZR_API_LISTEN_ADDR") {
            self.api.listen_addr = parse_env_value("BINDIZR_API_LISTEN_ADDR", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_PORT") {
            self.api.listen_port = parse_env_value("BINDIZR_API_PORT", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_REQUIRE_AUTHENTICATION") {
            self.api.require_authentication =
                parse_env_value("BINDIZR_API_REQUIRE_AUTHENTICATION", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_METRICS_ENABLED") {
            self.api.metrics_enabled = parse_env_value("BINDIZR_API_METRICS_ENABLED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_EXTERNAL_DNS_ENABLED") {
            self.api.external_dns_enabled =
                parse_env_value("BINDIZR_API_EXTERNAL_DNS_ENABLED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_OPENAPI_ENABLED") {
            self.api.openapi_enabled = parse_env_value("BINDIZR_API_OPENAPI_ENABLED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DATABASE_TYPE") {
            self.database.database_type = parse_env_value("BINDIZR_DATABASE_TYPE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_MYSQL_SERVER_URL") {
            self.database.mysql.server_url = value;
        }
        if let Some(value) = get_env("BINDIZR_POSTGRESQL_SERVER_URL") {
            self.database.postgresql.server_url = value;
        }
        if let Some(value) = get_env("BINDIZR_SQLITE_FILE_PATH") {
            self.database.sqlite.file_path = value;
        }
        if let Some(value) = get_env("BINDIZR_DATABASE_URL") {
            match self.database.database_type {
                DatabaseType::Mysql => self.database.mysql.server_url = value,
                DatabaseType::Postgresql => self.database.postgresql.server_url = value,
                DatabaseType::Sqlite => {}
            }
        }
        if let Some(value) = get_env("BINDIZR_DNS_PORT") {
            self.dns.listen_port = parse_env_value("BINDIZR_DNS_PORT", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_LISTEN_ADDR") {
            self.dns.listen_addr = parse_env_value("BINDIZR_DNS_LISTEN_ADDR", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_SECONDARY_ADDRS") {
            self.dns.secondary_addrs = value;
        }
        if let Some(value) = get_env("BINDIZR_NSUPDATE_ALLOW_UNSIGNED") {
            self.dns.nsupdate_allow_unsigned =
                parse_env_value("BINDIZR_NSUPDATE_ALLOW_UNSIGNED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_AFTER_UPDATE") {
            self.dns.notify_after_update = parse_env_value("BINDIZR_NOTIFY_AFTER_UPDATE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_MODE") {
            self.dns.notify_mode = parse_env_value("BINDIZR_NOTIFY_MODE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_BATCH_MS") {
            self.dns.notify_batch_ms = parse_env_value("BINDIZR_NOTIFY_BATCH_MS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_ZONE_CACHE") {
            self.dns.zone_cache = parse_env_value("BINDIZR_ZONE_CACHE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_ZONE_CACHE_MAX_MB") {
            self.dns.zone_cache_max_mb = parse_env_value("BINDIZR_ZONE_CACHE_MAX_MB", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_ON_STARTUP") {
            self.dns.notify_on_startup = parse_env_value("BINDIZR_NOTIFY_ON_STARTUP", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_RETRIES") {
            self.dns.notify_retries = parse_env_value("BINDIZR_NOTIFY_RETRIES", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_TIMEOUT_SECS") {
            self.dns.notify_timeout_secs = parse_env_value("BINDIZR_NOTIFY_TIMEOUT_SECS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_JOURNAL_RETENTION_DAYS") {
            self.dns.journal_retention_days =
                parse_env_value("BINDIZR_JOURNAL_RETENTION_DAYS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_LOG_LEVEL") {
            self.logging.log_level = parse_env_value("BINDIZR_LOG_LEVEL", &value)?;
        }

        Ok(())
    }
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

impl DatabaseConfig {
    fn validate(&self) -> Result<(), String> {
        match self.database_type {
            DatabaseType::Mysql if self.mysql.server_url.trim().is_empty() => Err(
                "database.mysql.server_url must not be empty when database.type is mysql"
                    .to_string(),
            ),
            DatabaseType::Postgresql if self.postgresql.server_url.trim().is_empty() => Err(
                "database.postgresql.server_url must not be empty when database.type is postgresql"
                    .to_string(),
            ),
            DatabaseType::Sqlite if self.sqlite.file_path.trim().is_empty() => Err(
                "database.sqlite.file_path must not be empty when database.type is sqlite"
                    .to_string(),
            ),
            _ => Ok(()),
        }
    }
}

impl ApiConfig {
    fn validate(&self) -> Result<(), String> {
        if self.listen_port == 0 {
            return Err("api.listen_port must not be 0".to_string());
        }
        Ok(())
    }
}

impl BindizrConfig {
    /// Both bind at startup, so sharing one leaves the second failing.
    fn validate_listeners(&self) -> Result<(), String> {
        if self.api.listen_port == self.dns.listen_port
            && (self.api.listen_addr == self.dns.listen_addr
                || self.api.listen_addr.is_unspecified()
                || self.dns.listen_addr.is_unspecified())
        {
            return Err(format!(
                "api and dns cannot share port {}",
                self.api.listen_port
            ));
        }
        Ok(())
    }
}

impl DnsConfig {
    fn validate(&self) -> Result<(), String> {
        if self.listen_port == 0 {
            return Err("dns.listen_port must not be 0".to_string());
        }
        // Zero would admit no zone at all, which zone_cache = false already says.
        if self.zone_cache && self.zone_cache_max_mb == 0 {
            return Err(
                "dns.zone_cache_max_mb must not be 0; set dns.zone_cache = false to disable the cache"
                    .to_string(),
            );
        }

        let raw = &self.secondary_addrs;
        if raw.trim().is_empty() {
            return Ok(());
        }
        // Separators only (e.g. ",") would otherwise read as "no secondaries".
        if raw.split(',').all(|entry| entry.trim().is_empty()) {
            return Err(
                "dns.secondary_addrs contains no addresses; use \"\" when there are no secondaries"
                    .to_string(),
            );
        }
        for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            // An unparseable entry silently notifies nobody and admits nobody.
            if !is_address_target(entry) {
                return Err(format!(
                    "dns.secondary_addrs entry '{}' is not a host[:port] address",
                    entry
                ));
            }
        }
        Ok(())
    }
}

/// Return the global configuration; panics if [`initialize`] has not run.
pub fn bindizr_config() -> &'static BindizrConfig {
    BINDIZR_CONFIG.get().expect("Configuration not initialized")
}
