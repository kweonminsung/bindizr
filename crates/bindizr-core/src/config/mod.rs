mod access_log;
mod activity_log;
mod api;
mod database;
mod dns;
mod env_overrides;
mod history;
mod logging;
mod transfer_log;

use std::net::{IpAddr, Ipv4Addr};
use std::{env, fs, io};

pub use access_log::{AccessLogConfig, SavedRequests};
pub use activity_log::ActivityLogConfig;
pub use api::{ApiConfig, ApiTlsConfig};
pub use database::{
    DatabaseConfig, DatabaseTlsConfig, DatabaseTlsMode, DatabaseType, MySqlConfig, PostgresConfig,
    SqliteConfig,
};
pub use dns::{
    DnsConfig, DnsTlsConfig, ImportConfig, NotifyConfig, NsupdateConfig, TransferConfig,
    ZoneDefaultsConfig,
};
pub use history::HistoryConfig;
pub use logging::{LogFormat, LogLevel, LoggingConfig};
use serde::{Deserialize, Serialize};
use thiserror::Error;
pub use transfer_log::{SavedTransfers, TransferLogConfig};

use crate::dns::name::ParseNameError;

/// The configuration file read when no path is given.
const DEFAULT_CONFIG_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

/// A one-word setting outside the words it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected {expected}")]
pub struct ParseConfigValueError {
    expected: &'static str,
}

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
    #[error(
        "invalid Bindizr configuration{}: {source}",
        line.map(|line| format!(" at line {line}")).unwrap_or_default()
    )]
    Parse {
        line: Option<usize>,
        #[source]
        source: toml::de::Error,
    },
    #[error("{name} environment variable is not valid UTF-8")]
    NonUnicodeEnv { name: &'static str },
    #[error("invalid {name} environment variable '{value}': {source}")]
    Env {
        name: &'static str,
        value: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
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
    #[error("dns.transfer.tls_required needs dns.tls.cert_file and dns.tls.key_file")]
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
    pub activity_log: ActivityLogConfig,
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
        let text = fs::read_to_string(config_path).map_err(|source| {
            let path = config_path.to_string();

            if source.kind() == io::ErrorKind::NotFound {
                ConfigError::NotFound { path }
            } else {
                ConfigError::Read { path, source }
            }
        })?;

        // A parse or validation failure names no file, and the path may be a
        // default the caller never spelled.
        Self::from_toml(&text, read_env).map_err(|source| ConfigError::InFile {
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
        if self.activity_log != next.activity_log {
            changed.push("activity_log".to_string());
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
        get_env: impl Fn(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let mut config = toml::from_str::<Self>(text).map_err(|mut source| {
            let line = source
                .span()
                .and_then(|span| text.as_bytes().get(..span.start))
                .map(|prefix| prefix.iter().filter(|byte| **byte == b'\n').count() + 1);

            // TOML errors include the entire file in Debug and source text in Display.
            source.set_input(None);
            ConfigError::Parse { line, source }
        })?;

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

/// Return the wildcard IPv4 address used by both listeners.
fn default_listen_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

/// The PEM certificate chain and private key a listener serves TLS with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsFiles<'a> {
    pub cert_file: &'a str,
    pub key_file: &'a str,
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

/// Resolve the config file path: explicit argument, then `BINDIZR_CONFIG_PATH`,
/// then the default path.
pub fn resolve_config_path(config_path: Option<&str>) -> Result<String, ConfigError> {
    resolve_config_path_with_env(config_path, read_env)
}

/// Resolve the configuration path using the supplied environment lookup.
fn resolve_config_path_with_env(
    config_path: Option<&str>,
    get_env: impl Fn(&'static str) -> Result<Option<String>, ConfigError>,
) -> Result<String, ConfigError> {
    match config_path {
        Some(path) => Ok(path.to_string()),
        None => {
            Ok(get_env("BINDIZR_CONFIG_PATH")?.unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string()))
        }
    }
}

/// Read an override without including invalid environment bytes in diagnostics.
fn read_env(name: &'static str) -> Result<Option<String>, ConfigError> {
    env::var_os(name)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| ConfigError::NonUnicodeEnv { name })
        })
        .transpose()
}

#[cfg(test)]
mod tests;
