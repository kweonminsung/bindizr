mod env_overrides;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::{env, fmt, fs, io};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::dns;
use crate::dns::name::{ParseNameError, ZoneName};
use crate::dns::{SoaInterval, Ttl};

/// The configuration file read when no path is given.
const DEFAULT_CONFIG_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

/// The longest idle timeout the edns-tcp-keepalive option carries.
const MAX_TCP_IDLE_TIMEOUT_SECS: u64 = 6553;

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
        source: io::Error,
    },
    /// A parse or validation failure, named with the file it came from.
    #[error("{source} (in {path})")]
    InFile {
        path: String,
        #[source]
        source: Box<Self>,
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
    /// RFC 7858, Section 3.1 keeps 853 for TLS and 53 for cleartext.
    #[error(
        "{section}.listen_port must not be {port}: it carries {reserved_for} (RFC 7858, Section 3.1)"
    )]
    PortReserved {
        section: &'static str,
        port: u16,
        reserved_for: &'static str,
    },
    #[error("{section}.{present} needs {section}.{missing}")]
    TlsHalfPair {
        section: &'static str,
        present: &'static str,
        missing: &'static str,
    },
    #[error("dns.transfer.require_tls needs dns.tls.cert_file and dns.tls.key_file")]
    TransferRequiresTlsListener,
    #[error("{key} must be between {min} and {max}")]
    OutOfRange {
        key: &'static str,
        min: u64,
        max: u64,
    },
    #[error("{key} must be at least 1")]
    Zero { key: &'static str },
    #[error("dns.catalog_zone_name is not a zone name: {0}")]
    CatalogZoneName(#[source] ParseNameError),
    #[error(
        "dns.catalog_zone_name must fit within {max_wire_len} wire octets, including the root, to leave room for generated catalog owners"
    )]
    CatalogZoneTooLong { max_wire_len: usize },
    /// A zero would stop secondaries refreshing, so a zone must not inherit it.
    #[error("dns.zone_defaults.{field} must be a positive number of seconds")]
    ZoneDefaultZero { field: &'static str },
}

/// Top-level bindizr configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub history: HistoryConfig,
    #[serde(default)]
    pub audit_log: AuditLogConfig,
    #[serde(default)]
    pub access_log: AccessLogConfig,
    #[serde(default)]
    pub transfer_log: TransferLogConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Config {
    /// Load and validate the file at `config_path`, applying environment
    /// overrides. The value is the caller's to hold; nothing is stored.
    pub fn load(config_path: &str) -> Result<Self, ConfigError> {
        if !PathBuf::from(config_path).exists() {
            return Err(ConfigError::NotFound {
                path: config_path.to_string(),
            });
        }

        let text = fs::read_to_string(config_path).map_err(|source| ConfigError::Read {
            path: config_path.to_string(),
            source,
        })?;

        // A parse or validation failure names no file, and the path may be a
        // default the caller never spelled.
        Self::from_toml(&text, |name| env::var(name).ok()).map_err(|source| ConfigError::InFile {
            path: config_path.to_string(),
            source: Box::new(source),
        })
    }

    /// List the settings a reload actually changed, for the line that reports it.
    pub fn changed_settings(&self, next: &Self) -> Vec<String> {
        let mut changed = Vec::new();

        if self.dns != next.dns {
            changed.push("dns".to_string());
        }
        if self.history != next.history {
            changed.push("history".to_string());
        }
        if self.audit_log != next.audit_log {
            changed.push("audit_log".to_string());
        }
        if self.access_log != next.access_log {
            changed.push("access_log".to_string());
        }
        if self.transfer_log != next.transfer_log {
            changed.push("transfer_log".to_string());
        }
        if self.logging != next.logging {
            changed.push("logging".to_string());
        }

        changed
    }

    /// List the settings bound to something built at startup — a listening socket,
    /// the HTTP router, the database pool — which a reload cannot rebuild.
    pub fn fixed_settings_changed(&self, next: &Self) -> Vec<String> {
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
        if self.dns.tls != next.dns.tls {
            fixed.push("dns.tls".to_string());
        }
        if self.dns.tcp_max_connections != next.dns.tcp_max_connections {
            fixed.push("dns.tcp_max_connections".to_string());
        }

        // A live rename would strand the catalog row and configured secondaries.
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
        let mut config = toml::from_str::<Self>(text).map_err(ConfigError::Parse)?;

        config.apply_env_overrides(get_env)?;
        config.api.validate()?;
        config.database.validate()?;
        config.dns.validate()?;
        config.validate_listeners()?;

        Ok(config)
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

/// HTTP API server settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: IpAddr,
    #[serde(default = "default_api_listen_port")]
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

impl ApiConfig {
    /// Validate the API configuration fields.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_port == 0 {
            return Err(ConfigError::PortZero { section: "api" });
        }
        self.tls.validate()
    }
}

impl Default for ApiConfig {
    /// Build the default HTTP listener and API settings.
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_api_listen_port(),
            authentication_required: default_authentication_required(),
            metrics_enabled: default_metrics_enabled(),
            external_dns_enabled: false,
            openapi_enabled: false,
            tls: ApiTlsConfig::default(),
        }
    }
}

/// Return the wildcard IPv4 address used by both listeners.
fn default_listen_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

/// Return the default HTTP API port.
fn default_api_listen_port() -> u16 {
    3000
}

/// The PEM certificate chain and private key a listener serves TLS with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsFiles<'a> {
    pub cert_file: &'a str,
    pub key_file: &'a str,
}

/// HTTPS for the API, served while both PEM files are set; without them the
/// bearer tokens travel in the clear.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTlsConfig {
    #[serde(default)]
    pub cert_file: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
}

impl ApiTlsConfig {
    /// Return the certificate and key to serve HTTPS with, or `None` for plain HTTP.
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
        validate_tls_pair(
            "api.tls",
            self.cert_file.as_deref(),
            self.key_file.as_deref(),
        )
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    #[serde(default, rename = "type")]
    pub database_type: DatabaseType,
    #[serde(default)]
    pub mysql: MySqlConfig,
    #[serde(default)]
    pub sqlite: SqliteConfig,
    #[serde(default)]
    pub postgresql: PostgresConfig,
    #[serde(default)]
    pub tls: DatabaseTlsConfig,
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

/// Supported database backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    MySql,
    #[default]
    Sqlite,
    #[serde(rename = "postgresql")]
    Postgres,
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

impl fmt::Display for DatabaseType {
    /// Write the database type in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DatabaseType {
    type Err = ConfigError;

    /// Parse a database type from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mysql" => Ok(Self::MySql),
            "sqlite" => Ok(Self::Sqlite),
            "postgresql" => Ok(Self::Postgres),
            _ => Err(ConfigError::UnknownValue {
                expected: "mysql, postgresql, or sqlite",
            }),
        }
    }
}

/// MySQL connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MySqlConfig {
    pub url: String,
}

/// SQLite connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    pub file_path: String,
}

/// PostgreSQL connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    pub url: String,
}

/// TLS to the MySQL or PostgreSQL server. A set key overrides the URL's own
/// parameter; unset leaves the URL and sqlx's default (TLS if offered, unverified).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseTlsMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl DatabaseTlsMode {
    /// Return the canonical wire spelling.
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

impl FromStr for DatabaseTlsMode {
    type Err = ConfigError;

    /// Parse a TLS mode from its configuration spelling.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
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

/// DNS server settings; the sub-tables hold the import client, NOTIFY,
/// nsupdate, the TLS listener, transfers, and zone defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: IpAddr,
    #[serde(default = "default_dns_listen_port")]
    pub listen_port: u16,
    /// Virtual RFC 9432 catalog zone name; primaries sharing a secondary need distinct names.
    #[serde(default = "default_catalog_zone_name")]
    pub catalog_zone_name: ZoneName,
    /// Seconds between scheduler passes for signing, rollover, and history pruning.
    /// 0 disables this instance; at least one instance must run the scheduler.
    #[serde(default = "default_scheduler_interval_secs")]
    pub scheduler_interval_secs: u64,
    /// Seconds a TCP or TLS connection may sit idle between queries;
    /// advertised as the edns-tcp-keepalive timeout (RFC 7828, Section 3.3.2).
    #[serde(default = "default_tcp_idle_timeout_secs")]
    pub tcp_idle_timeout_secs: u64,
    /// Connections served at once on each of the TCP and TLS listeners; the
    /// rest wait in the accept backlog.
    #[serde(default = "default_tcp_max_connections")]
    pub tcp_max_connections: usize,
    #[serde(default)]
    pub import: ImportConfig,
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

impl DnsConfig {
    /// Return whether a DNS question's decoded labels name this instance's catalog (RFC 4343).
    pub fn is_catalog_zone(&self, zone_name: &str) -> bool {
        ZoneName::parse(zone_name)
            .is_ok_and(|canonical_zone_name| canonical_zone_name == self.catalog_zone_name)
    }

    /// Return how long a TCP or TLS connection may sit idle between queries.
    pub fn tcp_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.tcp_idle_timeout_secs)
    }

    /// Validate the DNS configuration fields.
    fn validate(&self) -> Result<(), ConfigError> {
        let catalog_wire = self
            .catalog_zone_name
            .to_wire()
            .map_err(ConfigError::CatalogZoneName)?;

        if catalog_wire.len() > dns::MAX_CATALOG_ZONE_WIRE_LEN {
            return Err(ConfigError::CatalogZoneTooLong {
                max_wire_len: dns::MAX_CATALOG_ZONE_WIRE_LEN,
            });
        }
        if self.listen_port == 0 {
            return Err(ConfigError::PortZero { section: "dns" });
        }

        // RFC 7858, Section 3.1: servers "MUST NOT use port 853 to transport
        // cleartext DNS messages".
        if self.listen_port == 853 {
            return Err(ConfigError::PortReserved {
                section: "dns",
                port: 853,
                reserved_for: "DNS over TLS",
            });
        }

        // The idle timeout must fit the keepalive option's 16-bit deciseconds.
        if !(1..=MAX_TCP_IDLE_TIMEOUT_SECS).contains(&self.tcp_idle_timeout_secs) {
            return Err(ConfigError::OutOfRange {
                key: "dns.tcp_idle_timeout_secs",
                min: 1,
                max: MAX_TCP_IDLE_TIMEOUT_SECS,
            });
        }
        if self.tcp_max_connections == 0 {
            return Err(ConfigError::Zero {
                key: "dns.tcp_max_connections",
            });
        }

        self.tls.validate()?;
        self.import.validate()?;

        // Refusing plain transfers with no TLS listener would refuse them all.
        if self.transfer.require_tls && self.tls.tls_files().is_none() {
            return Err(ConfigError::TransferRequiresTlsListener);
        }

        // A zone without its own timers inherits these; unlike a requested
        // value, which may be zero, a default must be positive.
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

impl Default for DnsConfig {
    /// Build the default DNS listener and zone-management settings.
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_dns_listen_port(),
            catalog_zone_name: default_catalog_zone_name(),
            scheduler_interval_secs: default_scheduler_interval_secs(),
            tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
            tcp_max_connections: default_tcp_max_connections(),
            import: ImportConfig::default(),
            notify: NotifyConfig::default(),
            nsupdate: NsupdateConfig::default(),
            tls: DnsTlsConfig::default(),
            transfer: TransferConfig::default(),
            zone_defaults: ZoneDefaultsConfig::default(),
        }
    }
}

/// Return the default DNS port, leaving port 53 available to a secondary.
fn default_dns_listen_port() -> u16 {
    5300
}

/// When NOTIFY reaches the secondaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    /// NOTIFY coalescing window in milliseconds; queued sends follow the write response.
    /// Capped at SOA REFRESH from enqueue time; `0` sends every change before responding.
    #[serde(default)]
    pub batch_ms: u64,
    #[serde(default = "default_notify_retries")]
    pub retries: u32,
    /// Seconds to wait for each NOTIFY, SOA probe, and parent-NS query.
    #[serde(default = "default_notify_timeout_secs")]
    pub timeout_secs: u64,
}

impl NotifyConfig {
    /// Return how long one NOTIFY, probe, or resolution waits for its answer.
    pub fn timeout(self) -> Duration {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferConfig {
    /// Record budget for serial-keyed transfer caches, evicting least-recently-used zones.
    /// Oversized zones are served uncached; `0` disables caching.
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

/// nsupdate (RFC 2136).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Return the default idle timeout between queries on a connection.
fn default_tcp_idle_timeout_secs() -> u64 {
    30
}

/// Return the default number of connections served at once per listener.
fn default_tcp_max_connections() -> usize {
    128
}

/// `zone import --from-server`: the AXFR bindizr pulls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportConfig {
    /// Seconds the whole transfer may take, resolution included.
    #[serde(default = "default_import_timeout_secs")]
    pub timeout_secs: u64,
    /// Records a pulled zone may hold; a larger one is refused.
    #[serde(default = "default_import_max_records")]
    pub max_records: usize,
}

impl ImportConfig {
    /// Return how long the whole transfer may take.
    pub fn timeout(self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Validate the import bounds.
    fn validate(self) -> Result<(), ConfigError> {
        if self.timeout_secs == 0 {
            return Err(ConfigError::Zero {
                key: "dns.import.timeout_secs",
            });
        }
        if self.max_records == 0 {
            return Err(ConfigError::Zero {
                key: "dns.import.max_records",
            });
        }

        Ok(())
    }
}

impl Default for ImportConfig {
    /// Build the default import bounds.
    fn default() -> Self {
        Self {
            timeout_secs: default_import_timeout_secs(),
            max_records: default_import_max_records(),
        }
    }
}

/// Return the default deadline of a pulled transfer.
fn default_import_timeout_secs() -> u64 {
    30
}

/// Return the default record limit of a pulled zone.
fn default_import_max_records() -> usize {
    200_000
}

/// Zone transfers over TLS (XoT, RFC 9103): a second TCP listener on
/// `dns.listen_addr`, served while both PEM files are set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl DnsTlsConfig {
    /// Return the certificate and key to serve XoT with, or `None` while the TLS
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

        // RFC 7858, Section 3.1: DNS over TLS "MUST NOT be port 53".
        if self.listen_port == 53 {
            return Err(ConfigError::PortReserved {
                section: "dns.tls",
                port: 53,
                reserved_for: "cleartext DNS",
            });
        }

        // Half a pair would leave the listener off on a port the operator
        // means to serve, which no later error would reveal.
        validate_tls_pair(
            "dns.tls",
            self.cert_file.as_deref(),
            self.key_file.as_deref(),
        )
    }
}

/// Refuse half of `section`'s certificate and key pair: both are set or neither.
fn validate_tls_pair(
    section: &'static str,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<(), ConfigError> {
    match (cert_file, key_file) {
        (Some(_), None) => Err(ConfigError::TlsHalfPair {
            section,
            present: "cert_file",
            missing: "key_file",
        }),
        (None, Some(_)) => Err(ConfigError::TlsHalfPair {
            section,
            present: "key_file",
            missing: "cert_file",
        }),
        _ => Ok(()),
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneDefaultsConfig {
    #[serde(default = "default_zone_ttl")]
    pub ttl: Ttl,
    /// Short refresh/retry intervals limit staleness when NOTIFY is lost.
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
    Ttl::from_secs(3600)
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
    Ttl::from_secs(86400)
}

/// Return the default scheduler interval setting: plenty next to the
/// day-scale windows a pass enforces.
fn default_scheduler_interval_secs() -> u64 {
    3600
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

/// How long zone versions are kept, for diff and rollback, with the IXFR
/// journal behind incremental updates to secondaries; a pruned serial falls
/// back to AXFR. The scheduler pass prunes what is older.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryConfig {
    /// Days kept before the scheduler pass prunes older versions; `0` keeps
    /// them forever.
    #[serde(default = "default_history_max_days")]
    pub max_days: u32,
}

impl Default for HistoryConfig {
    /// Build the default zone history: a year.
    fn default() -> Self {
        Self {
            max_days: default_history_max_days(),
        }
    }
}

/// Return the default days of zone history kept.
fn default_history_max_days() -> u32 {
    365
}

/// The audit log of management changes, read under `/logs/audit`: how long
/// its entries are kept. Bindizr's own output is `[logging]`, not this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogConfig {
    /// Days kept before the scheduler pass prunes older entries; `0` keeps
    /// them forever.
    #[serde(default = "default_audit_log_max_days")]
    pub max_days: u32,
}

impl Default for AuditLogConfig {
    /// Build the default audit log settings: a year.
    fn default() -> Self {
        Self {
            max_days: default_audit_log_max_days(),
        }
    }
}

/// Return the default days of audit log kept.
fn default_audit_log_max_days() -> u32 {
    365
}

/// The access log of API requests and nsupdates, read under `/logs/access`:
/// which requests are saved, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLogConfig {
    #[serde(default)]
    pub save: SavedRequests,
    /// Days kept before the scheduler pass prunes older entries; `0` keeps
    /// them forever.
    #[serde(default = "default_access_log_max_days")]
    pub max_days: u32,
}

impl Default for AccessLogConfig {
    /// Build the default access log settings: every request, for 30 days.
    fn default() -> Self {
        Self {
            save: SavedRequests::default(),
            max_days: default_access_log_max_days(),
        }
    }
}

/// Return the default days of access log kept.
fn default_access_log_max_days() -> u32 {
    30
}

/// Which requests the access log saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedRequests {
    /// Every request answered, denied, or failed.
    #[default]
    All,
    /// Requests denied by authentication or authorization alone.
    Denied,
    /// No request: the access log stays empty.
    None,
}

impl SavedRequests {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Denied => "denied",
            Self::None => "none",
        }
    }
}

impl fmt::Display for SavedRequests {
    /// Write the setting in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SavedRequests {
    type Err = ConfigError;

    /// Parse the setting from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "denied" => Ok(Self::Denied),
            "none" => Ok(Self::None),
            _ => Err(ConfigError::UnknownValue {
                expected: "all, denied, or none",
            }),
        }
    }
}

/// The transfer log of what each client pulled, read under `/logs/transfer`:
/// which transfers are saved, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferLogConfig {
    #[serde(default)]
    pub save: SavedTransfers,
    /// Days kept before the scheduler pass prunes older entries; `0` keeps
    /// them forever. The newest transfer of each client and zone stays.
    #[serde(default = "default_transfer_log_max_days")]
    pub max_days: u32,
}

impl Default for TransferLogConfig {
    /// Build the default transfer log settings: every transfer, for 90 days.
    fn default() -> Self {
        Self {
            save: SavedTransfers::default(),
            max_days: default_transfer_log_max_days(),
        }
    }
}

/// Return the default days of transfer log kept.
fn default_transfer_log_max_days() -> u32 {
    90
}

/// Which transfers the transfer log saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedTransfers {
    /// Every transfer answered, refused, or failed.
    #[default]
    All,
    /// Refusals and failures alone.
    Unserved,
    /// No transfer: zone status and a secondary's summary then show none.
    None,
}

impl SavedTransfers {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Unserved => "unserved",
            Self::None => "none",
        }
    }
}

impl fmt::Display for SavedTransfers {
    /// Write the setting in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SavedTransfers {
    type Err = ConfigError;

    /// Parse the setting from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "unserved" => Ok(Self::Unserved),
            "none" => Ok(Self::None),
            _ => Err(ConfigError::UnknownValue {
                expected: "all, unserved, or none",
            }),
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default)]
    pub level: LogLevel,
    /// `json` writes one object per line for log pipelines.
    #[serde(default)]
    pub format: LogFormat,
}

/// The shape of each log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
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

impl fmt::Display for LogFormat {
    /// Write the log format in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LogFormat {
    type Err = ConfigError;

    /// Parse a log format from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err(ConfigError::UnknownValue {
                expected: "text or json",
            }),
        }
    }
}

/// Console log verbosity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
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

impl fmt::Display for LogLevel {
    /// Write the log level in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LogLevel {
    type Err = ConfigError;

    /// Parse a log level from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(ConfigError::UnknownValue {
                expected: "trace, debug, info, warn, or error",
            }),
        }
    }
}

/// Resolve the config file path: explicit argument, then `BINDIZR_CONFIG_PATH`,
/// then the default path.
pub fn resolve_config_path(config_path: Option<&str>) -> String {
    resolve_config_path_with_env(config_path, |name| env::var(name).ok())
}

/// Resolve the configuration path using the supplied environment lookup.
fn resolve_config_path_with_env(
    config_path: Option<&str>,
    get_env: impl Fn(&str) -> Option<String>,
) -> String {
    config_path
        .map(str::to_string)
        .or_else(|| get_env("BINDIZR_CONFIG_PATH"))
        .unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string())
}

#[cfg(test)]
mod tests;
