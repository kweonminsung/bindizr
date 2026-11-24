//! HTTP API listener and its HTTPS settings.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, TlsFiles, default_listen_addr, validate_tls_pair};

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
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

/// Return the default HTTP API port.
fn default_api_listen_port() -> u16 {
    3000
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

/// Return the default API authentication setting.
fn default_authentication_required() -> bool {
    true
}

/// Return the default metrics enabled setting.
fn default_metrics_enabled() -> bool {
    true
}
