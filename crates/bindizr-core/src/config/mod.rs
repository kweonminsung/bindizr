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
    #[error("{first} and {second} cannot share port {port}")]
    SharedPort {
        first: &'static str,
        second: &'static str,
        port: u16,
    },
    #[error(
        "database.tls.ca_file is checked only when database.tls.mode is verify-ca or verify-full"
    )]
    DatabaseTlsCaUnchecked,
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
    #[error("dns.transfer.require_tls needs dns.tls.cert_file and dns.tls.key_file")]
    TransferRequiresTlsListener,
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
    #[serde(default)]
    pub tls: ApiTlsConfig,
}

/// HTTPS for the API, served while both PEM files are set; without them the
/// bearer tokens travel in the clear.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiTlsConfig {
    #[serde(default)]
    pub cert_file: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
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
    #[serde(default)]
    pub tls: DatabaseTlsConfig,
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

/// TLS to the MySQL or PostgreSQL server. A set key overrides the URL's own
/// parameter; unset leaves the URL and sqlx's default (TLS if offered, unverified).
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct DatabaseTlsConfig {
    #[serde(default)]
    pub mode: Option<DatabaseTlsMode>,
    /// A private issuer to check the server's certificate against; the
    /// system roots otherwise.
    #[serde(default)]
    pub ca_file: Option<String>,
}

impl DatabaseTlsConfig {
    /// Validate the TLS fields.
    fn validate(&self) -> Result<(), ConfigError> {
        // A CA that no mode consults would read as protection it is not.
        if self.ca_file.is_some()
            && !matches!(
                self.mode,
                Some(DatabaseTlsMode::VerifyCa | DatabaseTlsMode::VerifyFull)
            )
        {
            return Err(ConfigError::DatabaseTlsCaUnchecked);
        }
        Ok(())
    }
}

/// How far the database connection insists on TLS, in PostgreSQL's words;
/// MySQL's modes map one to one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseTlsMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl DatabaseTlsMode {
    /// Return the canonical spelling, the configuration file's.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Prefer => "prefer",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        }
    }
}

impl fmt::Display for DatabaseTlsMode {
    /// Write the mode in its configuration spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DatabaseTlsMode {
    type Err = ConfigError;

    /// Parse a TLS mode from its configuration spelling.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disable" => Ok(Self::Disable),
            "prefer" => Ok(Self::Prefer),
            "require" => Ok(Self::Require),
            "verify-ca" => Ok(Self::VerifyCa),
            "verify-full" => Ok(Self::VerifyFull),
            _ => Err(ConfigError::UnknownValue {
                expected: "disable, prefer, require, verify-ca, or verify-full",
            }),
        }
    }
}

impl serde::Serialize for DatabaseTlsMode {
    /// Serialize through the canonical spelling.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl From<DatabaseTlsMode> for sqlx::postgres::PgSslMode {
    /// The same mode in sqlx's PostgreSQL vocabulary.
    fn from(mode: DatabaseTlsMode) -> Self {
        match mode {
            DatabaseTlsMode::Disable => Self::Disable,
            DatabaseTlsMode::Prefer => Self::Prefer,
            DatabaseTlsMode::Require => Self::Require,
            DatabaseTlsMode::VerifyCa => Self::VerifyCa,
            DatabaseTlsMode::VerifyFull => Self::VerifyFull,
        }
    }
}

impl From<DatabaseTlsMode> for sqlx::mysql::MySqlSslMode {
    /// The same mode in sqlx's MySQL vocabulary.
    fn from(mode: DatabaseTlsMode) -> Self {
        match mode {
            DatabaseTlsMode::Disable => Self::Disabled,
            DatabaseTlsMode::Prefer => Self::Preferred,
            DatabaseTlsMode::Require => Self::Required,
            DatabaseTlsMode::VerifyCa => Self::VerifyCa,
            DatabaseTlsMode::VerifyFull => Self::VerifyIdentity,
        }
    }
}

/// DNS server settings; NOTIFY, nsupdate, the TLS listener, transfers, and
/// zone defaults sit in sub-tables.
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
    #[serde(default)]
    pub notify: NotifyConfig,
    #[serde(default)]
    pub nsupdate: NsupdateConfig,
    #[serde(default)]
    pub tls: DnsTlsConfig,
    #[serde(default)]
    pub transfer: TransferConfig,
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

/// Zone transfers as bindizr serves them.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferConfig {
    /// Records the cache of each zone's transfer content, keyed by serial,
    /// may hold before evicting the least recently used zone. A zone larger
    /// than this is served uncached; `0` caches nothing.
    #[serde(default = "default_transfer_cache_max_records")]
    pub cache_max_records: u64,
    /// Refuse AXFR and IXFR over plain TCP and UDP (RFC 9103, Section 11);
    /// SOA queries keep answering. Needs `[dns.tls]`.
    #[serde(default)]
    pub require_tls: bool,
}

impl Default for TransferConfig {
    /// Build the default transfer settings.
    fn default() -> Self {
        Self {
            cache_max_records: default_transfer_cache_max_records(),
            require_tls: false,
        }
    }
}

/// RFC 2136 dynamic updates.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct NsupdateConfig {
    /// Require a TSIG signature on every update; `false` admits anyone.
    #[serde(default = "default_nsupdate_tsig_required")]
    pub tsig_required: bool,
}

impl Default for NsupdateConfig {
    /// Build the default nsupdate settings: signed updates only.
    fn default() -> Self {
        Self {
            tsig_required: default_nsupdate_tsig_required(),
        }
    }
}

/// Return the default nsupdate TSIG requirement.
fn default_nsupdate_tsig_required() -> bool {
    true
}

/// Zone transfers over TLS (XoT, RFC 9103): a second TCP listener on
/// `dns.listen_addr`, served while both PEM files are set.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsTlsConfig {
    /// 853 is the port DNS over TLS registers (RFC 7858, Section 3.1).
    #[serde(default = "default_dns_tls_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub cert_file: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
}

impl Default for DnsTlsConfig {
    /// Build the default TLS listener settings: the registered port, and no
    /// certificate, so the listener stays off.
    fn default() -> Self {
        Self {
            listen_port: default_dns_tls_listen_port(),
            cert_file: None,
            key_file: None,
        }
    }
}

/// Return the default DNS over TLS listen port.
fn default_dns_tls_listen_port() -> u16 {
    853
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
        // The TLS listener and its certificate are both built at startup.
        if self.dns.tls != next.dns.tls {
            fixed.push("dns.tls".to_string());
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

    /// Reject listeners sharing an endpoint so every server can bind at
    /// startup; the TLS listener counts only while it is on.
    fn validate_listeners(&self) -> Result<(), ConfigError> {
        let api = (self.api.listen_addr, self.api.listen_port);
        let dns = (self.dns.listen_addr, self.dns.listen_port);
        let dns_tls = (self.dns.listen_addr, self.dns.tls.listen_port);
        let dns_tls_on = self.dns.tls.tls_files().is_some();
        let pairs = [
            ("api", api, "dns", dns, true),
            ("dns", dns, "dns.tls", dns_tls, dns_tls_on),
            ("api", api, "dns.tls", dns_tls, dns_tls_on),
        ];
        for (first, (first_addr, port), second, (second_addr, second_port), checked) in pairs {
            // An unspecified address covers every other, so the port alone collides.
            if checked
                && port == second_port
                && (first_addr == second_addr
                    || first_addr.is_unspecified()
                    || second_addr.is_unspecified())
            {
                return Err(ConfigError::SharedPort {
                    first,
                    second,
                    port,
                });
            }
        }
        Ok(())
    }
}

impl DatabaseConfig {
    /// Validate the database configuration fields.
    fn validate(&self) -> Result<(), ConfigError> {
        self.tls.validate()?;
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

/// The PEM certificate chain and private key a listener serves TLS with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsFiles<'a> {
    pub cert_file: &'a str,
    pub key_file: &'a str,
}

impl ApiConfig {
    /// Validate the API configuration fields.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_port == 0 {
            return Err(ConfigError::PortZero { section: "api" });
        }
        self.tls.validate()
    }
}

impl ApiTlsConfig {
    /// The certificate and key to serve HTTPS with, or `None` for plain HTTP.
    pub fn tls_files(&self) -> Option<TlsFiles<'_>> {
        Some(TlsFiles {
            cert_file: self.cert_file.as_deref()?,
            key_file: self.key_file.as_deref()?,
        })
    }

    /// Validate the HTTPS fields.
    fn validate(&self) -> Result<(), ConfigError> {
        // Half a pair would serve plain HTTP on a port the operator means to
        // be HTTPS, which no later error would reveal.
        match (self.cert_file.as_deref(), self.key_file.as_deref()) {
            (Some(_), None) => Err(ConfigError::TlsHalfPair {
                present: "api.tls.cert_file",
                missing: "api.tls.key_file",
            }),
            (None, Some(_)) => Err(ConfigError::TlsHalfPair {
                present: "api.tls.key_file",
                missing: "api.tls.cert_file",
            }),
            _ => Ok(()),
        }
    }
}

impl DnsTlsConfig {
    /// The certificate and key to serve XoT with, or `None` while the TLS
    /// listener is off.
    pub fn tls_files(&self) -> Option<TlsFiles<'_>> {
        Some(TlsFiles {
            cert_file: self.cert_file.as_deref()?,
            key_file: self.key_file.as_deref()?,
        })
    }

    /// Validate the TLS listener fields.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_port == 0 {
            return Err(ConfigError::PortZero { section: "dns.tls" });
        }
        // Half a pair would leave the listener off on a port the operator
        // means to serve, which no later error would reveal.
        match (self.cert_file.as_deref(), self.key_file.as_deref()) {
            (Some(_), None) => Err(ConfigError::TlsHalfPair {
                present: "dns.tls.cert_file",
                missing: "dns.tls.key_file",
            }),
            (None, Some(_)) => Err(ConfigError::TlsHalfPair {
                present: "dns.tls.key_file",
                missing: "dns.tls.cert_file",
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
        self.tls.validate()?;
        // Refusing plain transfers with no TLS listener would refuse them all.
        if self.transfer.require_tls && self.tls.tls_files().is_none() {
            return Err(ConfigError::TransferRequiresTlsListener);
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
