mod env_overrides;

#[cfg(test)]
mod tests;

use std::{env, fmt, net::IpAddr, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::dns::{SoaInterval, Ttl, name::ZoneName};

/// Why the configuration could not be loaded or does not describe a runnable
/// process. Each message names the setting an operator would fix.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Bindizr config does not exist: {path}")]
    NotFound { path: String },
    #[error("failed to read the configuration file '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// A parse or validation failure, named with the file it came from.
    #[error("{source} (in {path})")]
    InFile {
        path: String,
        #[source]
        source: Box<ConfigError>,
    },
    #[error("invalid Bindizr configuration: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("invalid {name} environment variable '{value}': {source}")]
    Env {
        name: &'static str,
        value: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error("expected {expected}")]
    UnknownValue { expected: &'static str },
    #[error("api and dns cannot share port {port}")]
    SharedPort { port: u16 },
    #[error("{key} must not be empty when database.type is {database_type}")]
    EmptyDatabaseLocation {
        key: &'static str,
        database_type: DatabaseType,
    },
    #[error("{section}.listen_port must not be 0")]
    PortZero { section: &'static str },
    #[error("{present} needs {missing}")]
    TlsHalfPair {
        present: &'static str,
        missing: &'static str,
    },
    #[error("dns.catalog_zone_name is not a zone name: {0}")]
    CatalogZoneName(#[source] crate::dns::name::ParseNameError),
    /// A zero would stop secondaries refreshing, so a zone must not inherit it.
    #[error("dns.zone_defaults.{field} must be a positive number of seconds")]
    ZoneDefaultZero { field: &'static str },
}

const BINDIZR_CONF_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

/// Top-level bindizr configuration.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
}

/// HTTP API server settings.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Eq)]
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

/// Return the default catalog zone name.
fn default_catalog_zone_name() -> ZoneName {
    // RFC 9432, Section 3 leaves the name to the operator; this one says which
    // primary a secondary is holding the catalog of.
    ZoneName::from_row("catalog.bindizr")
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
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    MySql,
    Sqlite,
    #[serde(rename = "postgresql")]
    Postgres,
}

impl fmt::Display for DatabaseType {
    /// Write the database type in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DatabaseType {
    type Err = ConfigError;

    /// Parse a database type from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mysql" => Ok(DatabaseType::MySql),
            "sqlite" => Ok(DatabaseType::Sqlite),
            "postgresql" => Ok(DatabaseType::Postgres),
            _ => Err(ConfigError::UnknownValue {
                expected: "mysql, postgresql, or sqlite",
            }),
        }
    }
}

/// MySQL connection settings.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct MysqlConfig {
    pub url: String,
}

/// SQLite connection settings.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    pub file_path: String,
}

/// PostgreSQL connection settings.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlConfig {
    pub url: String,
}

/// DNS server settings; NOTIFY and the transfer cache sit in sub-tables.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    /// Name of the virtual RFC 9432 catalog zone this instance serves. A
    /// secondary holds one zone per name, so two primaries feeding the same
    /// secondary need two names.
    #[serde(default = "default_catalog_zone_name")]
    pub catalog_zone_name: ZoneName,
    /// Days of zone history to keep (0 = unlimited): the IXFR journal and the
    /// versions rollback can reach. A secondary asking for a pruned serial
    /// falls back to AXFR.
    #[serde(default = "default_zone_history_retention_days")]
    pub zone_history_retention_days: u32,
    /// Seconds between scheduler passes for signing, rollover, and history pruning.
    /// 0 disables this instance; at least one instance must run the scheduler.
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
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
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

impl NotifyConfig {
    /// How long one NOTIFY, probe, or resolution waits for its answer.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

impl Default for NotifyConfig {
    /// Build the default NOTIFY settings.
    fn default() -> Self {
        Self {
            batch_ms: 0,
            retries: default_notify_retries(),
            timeout_secs: default_notify_timeout_secs(),
        }
    }
}

/// The cache of each zone's transfer content, keyed by serial, so repeated
/// AXFRs skip the database read.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferCacheConfig {
    /// Records the cache may hold before evicting the least recently used
    /// zone. A zone larger than this is served uncached; `0` caches nothing.
    #[serde(default = "default_transfer_cache_max_records")]
    pub max_records: u64,
}

impl Default for TransferCacheConfig {
    /// Build the default transfer cache settings.
    fn default() -> Self {
        Self {
            max_records: default_transfer_cache_max_records(),
        }
    }
}

/// What a zone takes when its creation request leaves a field out. Only the
/// creation reads these: afterwards the values are the zone's own columns.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct ZoneDefaultsConfig {
    #[serde(default = "default_zone_ttl")]
    pub ttl: Ttl,
    /// Bindizr drives propagation with NOTIFY, so refresh and retry stay
    /// short: they bound how long a secondary stays stale when a NOTIFY is
    /// lost, not the happy-path latency.
    #[serde(default = "default_zone_refresh")]
    pub refresh: SoaInterval,
    #[serde(default = "default_zone_retry")]
    pub retry: SoaInterval,
    #[serde(default = "default_zone_expire")]
    pub expire: SoaInterval,
    #[serde(default = "default_zone_minimum_ttl")]
    pub minimum_ttl: Ttl,
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
fn default_zone_ttl() -> Ttl {
    Ttl::from_secs(3_600)
}

/// Return the default zone refresh setting.
fn default_zone_refresh() -> SoaInterval {
    SoaInterval::from_secs(300)
}

/// Return the default zone retry setting.
fn default_zone_retry() -> SoaInterval {
    SoaInterval::from_secs(60)
}

/// Return the default zone expire setting.
fn default_zone_expire() -> SoaInterval {
    SoaInterval::from_secs(3_600_000)
}

/// Return the default zone minimum TTL setting.
fn default_zone_minimum_ttl() -> Ttl {
    Ttl::from_secs(86_400)
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
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: LogLevel,
    /// `json` writes one object per line for log pipelines.
    #[serde(default)]
    pub format: LogFormat,
}

/// The shape of each log line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl fmt::Display for LogFormat {
    /// Write the log format in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LogFormat {
    type Err = ConfigError;

    /// Parse a log format from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "text" => Ok(LogFormat::Text),
            "json" => Ok(LogFormat::Json),
            _ => Err(ConfigError::UnknownValue {
                expected: "text or json",
            }),
        }
    }
}

/// Console log verbosity levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
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
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LogLevel {
    type Err = ConfigError;

    /// Parse a log level from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(ConfigError::UnknownValue {
                expected: "trace, debug, info, warn, or error",
            }),
        }
    }
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

impl Config {
    /// Load and validate the file at `conf_file_path`, applying environment
    /// overrides. The value is the caller's to hold; nothing is stored.
    pub fn load(conf_file_path: &str) -> Result<Config, ConfigError> {
        if !PathBuf::from(conf_file_path).exists() {
            return Err(ConfigError::NotFound {
                path: conf_file_path.to_string(),
            });
        }

        let text = std::fs::read_to_string(conf_file_path).map_err(|source| ConfigError::Read {
            path: conf_file_path.to_string(),
            source,
        })?;
        // A parse or validation failure names no file, and the path may be a
        // default the caller never spelled.
        Config::from_toml(&text, |name| env::var(name).ok()).map_err(|source| ConfigError::InFile {
            path: conf_file_path.to_string(),
            source: Box::new(source),
        })
    }

    /// The settings a reload actually changed, for the line that reports it.
    pub fn changed_settings(&self, next: &Config) -> Vec<String> {
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
    pub fn fixed_settings_changed(&self, next: &Config) -> Vec<String> {
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
        // Renaming the catalog live would strand its stored row and the
        // secondaries configured to request its old name.
        if self.dns.catalog_zone_name != next.dns.catalog_zone_name {
            fixed.push("dns.catalog_zone_name".to_string());
        }
        fixed
    }

    /// Assemble the effective configuration from its raw sections.
    fn from_toml(
        text: &str,
        get_env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let mut bindizr_config = toml::from_str::<Self>(text).map_err(ConfigError::Parse)?;

        bindizr_config.apply_env_overrides(get_env)?;
        bindizr_config.api.validate()?;
        bindizr_config.database.validate()?;
        bindizr_config.dns.validate()?;
        bindizr_config.validate_listeners()?;

        Ok(bindizr_config)
    }

    /// Reject overlapping API and DNS endpoints so both servers can bind at startup.
    fn validate_listeners(&self) -> Result<(), ConfigError> {
        if self.api.listen_port == self.dns.listen_port
            && (self.api.listen_addr == self.dns.listen_addr
                || self.api.listen_addr.is_unspecified()
                || self.dns.listen_addr.is_unspecified())
        {
            return Err(ConfigError::SharedPort {
                port: self.api.listen_port,
            });
        }
        Ok(())
    }
}

impl DatabaseConfig {
    /// Validate the database configuration fields.
    fn validate(&self) -> Result<(), ConfigError> {
        match self.database_type {
            DatabaseType::MySql if self.mysql.url.trim().is_empty() => {
                Err(ConfigError::EmptyDatabaseLocation {
                    key: "database.mysql.url",
                    database_type: DatabaseType::MySql,
                })
            }
            DatabaseType::Postgres if self.postgresql.url.trim().is_empty() => {
                Err(ConfigError::EmptyDatabaseLocation {
                    key: "database.postgresql.url",
                    database_type: DatabaseType::Postgres,
                })
            }
            DatabaseType::Sqlite if self.sqlite.file_path.trim().is_empty() => {
                Err(ConfigError::EmptyDatabaseLocation {
                    key: "database.sqlite.file_path",
                    database_type: DatabaseType::Sqlite,
                })
            }
            _ => Ok(()),
        }
    }
}

/// The certificate and key files the API serves HTTPS with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsFiles<'a> {
    pub cert_file: &'a str,
    pub key_file: &'a str,
}

impl ApiConfig {
    /// The certificate and key to serve HTTPS with, or `None` for plain HTTP.
    pub fn tls_files(&self) -> Option<TlsFiles<'_>> {
        Some(TlsFiles {
            cert_file: self.tls_cert_file.as_deref()?,
            key_file: self.tls_key_file.as_deref()?,
        })
    }

    /// Validate the API configuration fields.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_port == 0 {
            return Err(ConfigError::PortZero { section: "api" });
        }
        // Half a pair would serve plain HTTP on a port the operator means to
        // be HTTPS, which no later error would reveal.
        match (self.tls_cert_file.as_deref(), self.tls_key_file.as_deref()) {
            (Some(_), None) => Err(ConfigError::TlsHalfPair {
                present: "api.tls_cert_file",
                missing: "api.tls_key_file",
            }),
            (None, Some(_)) => Err(ConfigError::TlsHalfPair {
                present: "api.tls_key_file",
                missing: "api.tls_cert_file",
            }),
            _ => Ok(()),
        }
    }
}

impl DnsConfig {
    /// Whether `zone_name` is the virtual RFC 9432 catalog zone this instance
    /// serves. Case-insensitive per RFC 4343; callers pass client-cased query
    /// names as-is.
    pub fn is_catalog_zone(&self, zone_name: &str) -> bool {
        zone_name.eq_ignore_ascii_case(self.catalog_zone_name.as_str())
    }

    /// Validate the DNS configuration fields.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_port == 0 {
            return Err(ConfigError::PortZero { section: "dns" });
        }
        // A zone without its own timers inherits these; a zero is refused
        // here as it is in a request.
        let defaults = &self.zone_defaults;
        for (field, secs) in [
            ("refresh", defaults.refresh.as_secs()),
            ("retry", defaults.retry.as_secs()),
            ("expire", defaults.expire.as_secs()),
            ("minimum_ttl", defaults.minimum_ttl.as_secs()),
        ] {
            if secs == 0 {
                return Err(ConfigError::ZoneDefaultZero { field });
            }
        }
        Ok(())
    }
}

impl DatabaseType {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgresql",
        }
    }
}

impl serde::Serialize for DatabaseType {
    /// Serialize through the canonical spelling used by the wire contract.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl LogFormat {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

impl serde::Serialize for LogFormat {
    /// Serialize through the canonical spelling used by the wire contract.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl LogLevel {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl serde::Serialize for LogLevel {
    /// Serialize through the canonical spelling used by the wire contract.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
