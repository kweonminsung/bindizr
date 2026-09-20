mod environment;

#[cfg(test)]
mod tests;

use std::{
    env, fmt,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, OnceLock, RwLock},
};

use serde::{Deserialize, Serialize};

use crate::dns::address::is_address_target;

const BINDIZR_CONF_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

/// Swappable so `reload` can replace it; readers take a snapshot, so a
/// request decides on one version throughout even if a reload lands mid-way.
static BINDIZR_CONFIG: RwLock<Option<Arc<BindizrConfig>>> = RwLock::new(None);

/// The file `reload` re-reads. Fixed at startup: a reload changes settings,
/// never which file they come from.
static CONFIG_PATH: OnceLock<String> = OnceLock::new();

/// Top-level bindizr configuration.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindizrConfig {
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
}

/// HTTP API server settings.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    /// Require an API token on every request that touches zone data.
    #[serde(default = "default_authentication_required")]
    pub authentication_required: bool,
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

/// Return the default nsupdate TSIG requirement.
fn default_nsupdate_tsig_required() -> bool {
    true
}

/// Return the default API authentication setting.
fn default_authentication_required() -> bool {
    true
}

/// Return the default metrics enabled setting.
fn default_metrics_enabled() -> bool {
    true
}

/// Database backend selection and per-backend connection settings.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    /// Write the database type in its display form.
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

    /// Parse a database type from its text representation.
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
#[serde(deny_unknown_fields)]
pub struct MysqlConfig {
    pub url: String,
}

/// SQLite connection settings.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    pub file_path: String,
}

/// PostgreSQL connection settings.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlConfig {
    pub url: String,
}

/// DNS server settings; NOTIFY and the transfer cache sit in sub-tables.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub secondary_addrs: String,
    /// Days of zone history to keep (0 = unlimited): the IXFR journal and the
    /// versions rollback can reach. A secondary asking for a pruned serial
    /// falls back to AXFR.
    #[serde(default = "default_zone_history_retention_days")]
    pub zone_history_retention_days: u32,
    /// Seconds between passes of the background scheduler: signature renewal,
    /// key rollover steps, and zone history pruning. `0` runs no pass on this
    /// instance; every instance runs the whole pass, so all but one may turn
    /// it off, but not all.
    #[serde(default = "default_scheduler_interval_secs")]
    pub scheduler_interval_secs: u64,
    /// Require a TSIG signature on RFC 2136 updates.
    #[serde(default = "default_nsupdate_tsig_required")]
    pub nsupdate_tsig_required: bool,
    #[serde(default)]
    pub notify: NotifyConfig,
    #[serde(default)]
    pub transfer_cache: TransferCacheConfig,
    #[serde(default)]
    pub zone_defaults: ZoneDefaultsConfig,
}

/// When NOTIFY reaches the secondaries.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    #[serde(default = "default_notify_after_update")]
    pub after_update: bool,
    #[serde(default)]
    pub on_startup: bool,
    /// Window (ms) that collects one zone's changes into one NOTIFY, sent
    /// from a queue after the write is answered. `0` sends a NOTIFY for
    /// every change before the write is answered.
    #[serde(default)]
    pub batch_ms: u64,
    #[serde(default = "default_notify_retries")]
    pub retries: u32,
    #[serde(default = "default_notify_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for NotifyConfig {
    /// Build the default NOTIFY settings.
    fn default() -> Self {
        Self {
            after_update: default_notify_after_update(),
            on_startup: false,
            batch_ms: 0,
            retries: default_notify_retries(),
            timeout_secs: default_notify_timeout_secs(),
        }
    }
}

/// The cache of each zone's transfer content, keyed by serial, so repeated
/// AXFRs skip the database read.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferCacheConfig {
    #[serde(default = "default_transfer_cache_enabled")]
    pub enabled: bool,
    /// Records the cache may hold before evicting the least recently used
    /// zone. A zone larger than this is served uncached.
    #[serde(default = "default_transfer_cache_max_records")]
    pub max_records: u64,
}

impl Default for TransferCacheConfig {
    /// Build the default transfer cache settings.
    fn default() -> Self {
        Self {
            enabled: default_transfer_cache_enabled(),
            max_records: default_transfer_cache_max_records(),
        }
    }
}

/// What a zone takes when its creation request leaves a field out. Only the
/// creation reads these: afterwards the values are the zone's own columns.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    /// Build the default zone settings.
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

/// Return the default zone TTL setting.
fn default_zone_ttl() -> i32 {
    3_600
}

/// Return the default zone refresh setting.
fn default_zone_refresh() -> i32 {
    300
}

/// Return the default zone retry setting.
fn default_zone_retry() -> i32 {
    60
}

/// Return the default zone expire setting.
fn default_zone_expire() -> i32 {
    3_600_000
}

/// Return the default zone minimum TTL setting.
fn default_zone_minimum_ttl() -> i32 {
    86_400
}

/// Return the default zone history retention days setting.
fn default_zone_history_retention_days() -> u32 {
    365
}

/// Return the default scheduler interval setting: plenty next to the
/// day-scale windows a pass enforces.
fn default_scheduler_interval_secs() -> u64 {
    3_600
}

/// Return the default notify after update setting.
fn default_notify_after_update() -> bool {
    true
}

/// Return the default transfer cache enabled setting.
fn default_transfer_cache_enabled() -> bool {
    true
}

/// Return the default transfer cache max records setting.
fn default_transfer_cache_max_records() -> u64 {
    500_000
}

/// Return the default notify retries setting.
fn default_notify_retries() -> u32 {
    3
}

/// Return the default notify timeout secs setting.
fn default_notify_timeout_secs() -> u64 {
    3
}

/// Logging settings.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: LogLevel,
    /// `json` writes one object per line for log pipelines.
    #[serde(default)]
    pub format: LogFormat,
}

/// The shape of each log line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl fmt::Display for LogFormat {
    /// Write the log format in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            LogFormat::Text => "text",
            LogFormat::Json => "json",
        };
        write!(f, "{}", value)
    }
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    /// Parse a log format from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "text" => Ok(LogFormat::Text),
            "json" => Ok(LogFormat::Json),
            _ => Err("expected text or json".to_string()),
        }
    }
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
    /// Write the log level in its display form.
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

    /// Parse a log level from its text representation.
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
/// apply environment overrides, and store it as the global config, returning
/// the file it came from: the logger is installed from what this loads, so
/// only the caller can report it in the configured format.
pub fn initialize(conf_file_path: Option<&str>) -> Result<String, String> {
    let conf_file_path = resolve_config_path(conf_file_path);

    let bindizr_config = load_config_file(&conf_file_path)?;
    let mut stored = BINDIZR_CONFIG.write().map_err(|_| POISONED)?;
    if stored.is_some() {
        return Err("Bindizr configuration is already initialized".to_string());
    }
    let _ = CONFIG_PATH.set(conf_file_path.clone());
    *stored = Some(Arc::new(bindizr_config));

    Ok(conf_file_path)
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

    let fixed = current.fixed_settings_changed(&next);
    if !fixed.is_empty() {
        return Err(format!(
            "these settings are fixed while bindizr runs, so nothing was reloaded: {}",
            fixed.join(", ")
        ));
    }

    let changed = current.changed_settings(&next);
    *stored = Some(Arc::new(next));
    Ok(changed)
}

/// Resolve the config file path: explicit argument, then `BINDIZR_CONFIG_PATH`,
/// then the default path.
pub fn resolve_config_path(conf_file_path: Option<&str>) -> String {
    resolve_config_path_with_env(conf_file_path, |name| env::var(name).ok())
}

/// Resolve the configuration path using the supplied environment lookup.
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

    let text = std::fs::read_to_string(conf_file_path).map_err(|e| {
        format!(
            "Failed to read the configuration file '{}': {}",
            conf_file_path, e
        )
    })?;
    // A parse or validation failure names no file, and the path may be a
    // default the caller never spelled.
    BindizrConfig::from_toml(&text, |name| env::var(name).ok())
        .map_err(|e| format!("{} (in {})", e, conf_file_path))
}

impl BindizrConfig {
    /// The settings a reload actually changed, for the line that reports it.
    fn changed_settings(&self, next: &BindizrConfig) -> Vec<String> {
        let mut changed = Vec::new();
        if self.dns != next.dns {
            changed.push("dns".to_string());
        }
        if self.logging != next.logging {
            changed.push("logging".to_string());
        }
        changed
    }

    /// Settings bound to something built at startup — a listening socket, the
    /// HTTP router, the database pool — which a reload cannot rebuild.
    fn fixed_settings_changed(&self, next: &BindizrConfig) -> Vec<String> {
        let mut fixed = Vec::new();
        if self.api != next.api {
            fixed.push("api".to_string());
        }
        if self.database != next.database {
            fixed.push("database".to_string());
        }
        if self.dns.listen_addr != next.dns.listen_addr {
            fixed.push("dns.listen_addr".to_string());
        }
        if self.dns.listen_port != next.dns.listen_port {
            fixed.push("dns.listen_port".to_string());
        }
        fixed
    }

    /// Assemble the effective configuration from its raw sections.
    fn from_toml(text: &str, get_env: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut bindizr_config = toml::from_str::<Self>(text)
            .map_err(|e| format!("Invalid Bindizr configuration: {}", e))?;

        bindizr_config.apply_env_overrides(get_env)?;
        bindizr_config.api.validate()?;
        bindizr_config.database.validate()?;
        bindizr_config.dns.validate()?;
        bindizr_config.validate_listeners()?;

        Ok(bindizr_config)
    }

    /// Reject overlapping API and DNS endpoints so both servers can bind at startup.
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

impl DatabaseConfig {
    /// Validate the database configuration fields.
    fn validate(&self) -> Result<(), String> {
        match self.database_type {
            DatabaseType::Mysql if self.mysql.url.trim().is_empty() => {
                Err("database.mysql.url must not be empty when database.type is mysql".to_string())
            }
            DatabaseType::Postgresql if self.postgresql.url.trim().is_empty() => Err(
                "database.postgresql.url must not be empty when database.type is postgresql"
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

    /// Validate the API configuration fields.
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

impl DnsConfig {
    /// Validate the DNS configuration fields.
    fn validate(&self) -> Result<(), String> {
        if self.listen_port == 0 {
            return Err("dns.listen_port must not be 0".to_string());
        }
        // Zero would admit no zone at all, which enabled = false already says.
        if self.transfer_cache.enabled && self.transfer_cache.max_records == 0 {
            return Err(
                "dns.transfer_cache.max_records must not be 0; set dns.transfer_cache.enabled = false to disable the cache"
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
