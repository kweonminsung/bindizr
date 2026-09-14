mod environment;

#[cfg(test)]
mod tests;

use std::{
    env, fmt,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, OnceLock, RwLock},
};

use config::{Config, File, FileFormat};
use serde::{Deserialize, Serialize};

use crate::dns::address::is_address_target;

pub(crate) const BINDIZR_CONF_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

/// Swappable so `reload` can replace it; readers take a snapshot, so a
/// request decides on one version throughout even if a reload lands mid-way.
static BINDIZR_CONFIG: RwLock<Option<Arc<BindizrConfig>>> = RwLock::new(None);

/// The file `reload` re-reads. Fixed at startup: a reload changes settings,
/// never which file they come from.
static CONFIG_PATH: OnceLock<String> = OnceLock::new();

/// Top-level bindizr configuration.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct BindizrConfig {
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
}

/// HTTP API server settings.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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
    /// PEM certificate chain and private key. Set both to serve HTTPS;
    /// without them the API is plain HTTP and its bearer tokens travel in
    /// the clear.
    #[serde(default)]
    pub tls_cert_file: Option<String>,
    #[serde(default)]
    pub tls_key_file: Option<String>,
}

fn default_metrics_enabled() -> bool {
    true
}

/// Database backend selection and per-backend connection settings.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct MysqlConfig {
    pub server_url: String,
}

/// SQLite connection settings.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct SqliteConfig {
    pub file_path: String,
}

/// PostgreSQL connection settings.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct PostgresqlConfig {
    pub server_url: String,
}

/// DNS server and NOTIFY/nsupdate settings.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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
    /// Records the zone cache may hold before evicting the least recently
    /// used zone. A zone larger than this is served uncached.
    #[serde(default = "default_zone_cache_max_records")]
    pub zone_cache_max_records: u64,
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
    /// Seconds between maintenance passes: signature refresh, journal
    /// retention, and the rollover steps that advance on a deadline or the
    /// parent's DS. `0` runs no pass on this instance — every instance runs
    /// the whole pass, so all but one may turn it off, but not all.
    #[serde(default = "default_maintenance_interval_secs")]
    pub maintenance_interval_secs: u64,
    #[serde(default)]
    pub zone_defaults: ZoneDefaultsConfig,
}

/// What a zone takes when its creation request leaves a field out. Only the
/// creation reads these: afterwards the values are the zone's own columns.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ZoneDefaultsConfig {
    #[serde(default = "default_zone_ttl")]
    pub ttl: i32,
    /// Bindizr drives propagation with NOTIFY, so refresh and retry stay
    /// short: they bound how long a secondary stays stale when a NOTIFY is
    /// lost, not the happy-path latency.
    #[serde(default = "default_zone_refresh")]
    pub refresh: i32,
    #[serde(default = "default_zone_retry")]
    pub retry: i32,
    #[serde(default = "default_zone_expire")]
    pub expire: i32,
    #[serde(default = "default_zone_minimum_ttl")]
    pub minimum_ttl: i32,
}

impl Default for ZoneDefaultsConfig {
    fn default() -> Self {
        Self {
            ttl: default_zone_ttl(),
            refresh: default_zone_refresh(),
            retry: default_zone_retry(),
            expire: default_zone_expire(),
            minimum_ttl: default_zone_minimum_ttl(),
        }
    }
}

fn default_zone_ttl() -> i32 {
    3_600
}

fn default_zone_refresh() -> i32 {
    300
}

fn default_zone_retry() -> i32 {
    60
}

fn default_zone_expire() -> i32 {
    3_600_000
}

fn default_zone_minimum_ttl() -> i32 {
    86_400
}

fn default_journal_retention_days() -> u32 {
    365
}

/// Plenty next to the day-scale windows a pass enforces.
fn default_maintenance_interval_secs() -> u64 {
    3_600
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

fn default_zone_cache_max_records() -> u64 {
    500_000
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
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub log_level: LogLevel,
}

/// Console log verbosity levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
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
    let mut stored = BINDIZR_CONFIG.write().map_err(|_| POISONED)?;
    if stored.is_some() {
        return Err("Bindizr configuration is already initialized".to_string());
    }
    let _ = CONFIG_PATH.set(conf_file_path);
    *stored = Some(Arc::new(bindizr_config));

    Ok(())
}

const POISONED: &str = "Bindizr configuration lock is poisoned";

/// Re-read the configuration file and replace the stored one, returning the
/// settings that changed. Settings a running process cannot adopt are refused
/// rather than stored, so the configuration always describes the process.
pub fn reload() -> Result<Vec<String>, String> {
    let path = CONFIG_PATH
        .get()
        .ok_or("Bindizr configuration is not initialized")?;
    let next = load_config_file(path)?;

    let mut stored = BINDIZR_CONFIG.write().map_err(|_| POISONED)?;
    let current = stored
        .as_ref()
        .ok_or("Bindizr configuration is not initialized")?;

    let fixed = fixed_settings_changed(current, &next);
    if !fixed.is_empty() {
        return Err(format!(
            "these settings are fixed while bindizr runs, so nothing was reloaded: {}",
            fixed.join(", ")
        ));
    }

    let changed = changed_settings(current, &next);
    *stored = Some(Arc::new(next));
    Ok(changed)
}

/// The settings a reload actually changed, for the line that reports it.
fn changed_settings(current: &BindizrConfig, next: &BindizrConfig) -> Vec<String> {
    let mut changed = Vec::new();
    if current.dns != next.dns {
        changed.push("dns".to_string());
    }
    if current.logging != next.logging {
        changed.push("logging".to_string());
    }
    changed
}

/// Settings bound to something built at startup — a listening socket, the
/// HTTP router, the database pool — which a reload cannot rebuild.
fn fixed_settings_changed(current: &BindizrConfig, next: &BindizrConfig) -> Vec<String> {
    let mut fixed = Vec::new();
    if current.api != next.api {
        fixed.push("api".to_string());
    }
    if current.database != next.database {
        fixed.push("database".to_string());
    }
    if current.dns.listen_addr != next.dns.listen_addr {
        fixed.push("dns.listen_addr".to_string());
    }
    if current.dns.listen_port != next.dns.listen_port {
        fixed.push("dns.listen_port".to_string());
    }
    fixed
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

    let cfg = Config::builder()
        .add_source(File::new(conf_file_path, FileFormat::Toml).required(true))
        .build()
        .map_err(|e| {
            format!(
                "Failed to build configuration from file '{}': {}",
                conf_file_path, e
            )
        })?;
    BindizrConfig::from_raw(cfg, |name| env::var(name).ok())
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
    /// The certificate and key to serve HTTPS with, or `None` for plain HTTP.
    pub fn tls_files(&self) -> Option<(&str, &str)> {
        Some((
            self.tls_cert_file.as_deref()?,
            self.tls_key_file.as_deref()?,
        ))
    }

    fn validate(&self) -> Result<(), String> {
        if self.listen_port == 0 {
            return Err("api.listen_port must not be 0".to_string());
        }
        // Half a pair would serve plain HTTP on a port the operator means to
        // be HTTPS, which no later error would reveal.
        match (self.tls_cert_file.as_deref(), self.tls_key_file.as_deref()) {
            (Some(_), None) => Err("api.tls_cert_file needs api.tls_key_file".to_string()),
            (None, Some(_)) => Err("api.tls_key_file needs api.tls_cert_file".to_string()),
            _ => Ok(()),
        }
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
        if self.zone_cache && self.zone_cache_max_records == 0 {
            return Err(
                "dns.zone_cache_max_records must not be 0; set dns.zone_cache = false to disable the cache"
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

/// A snapshot of the global configuration; panics if [`initialize`] has not
/// run. A reload is invisible to a snapshot already taken, so hold one for
/// as long as a single decision takes and no longer.
pub fn bindizr_config() -> Arc<BindizrConfig> {
    BINDIZR_CONFIG
        .read()
        .expect(POISONED)
        .clone()
        .expect("Configuration not initialized")
}
