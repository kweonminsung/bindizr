//! Read adapter flags/environment; the adapter runs beside external-dns and does not read bindizr's config.

use std::net::SocketAddr;
use std::str::FromStr;
use std::{fmt, fs, io};

use bindizr_core::config::{LogLevel, ParseConfigValueError};
use clap::Parser;
use reqwest::Url;
use thiserror::Error;

/// A configured value that must stay out of diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RedactedString(String);

impl RedactedString {
    /// Borrow the value for validation or authentication.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for RedactedString {
    /// Hold a configured value without exposing it through Debug.
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for RedactedString {
    /// Redact the entire value, including in alternate formatting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Why the configured bindizr base URL could not be used.
#[derive(Debug, Error)]
pub(crate) enum ParseBindizrUrlError {
    #[error("must start with http:// or https://")]
    Scheme,
    #[error("{0}")]
    Invalid(#[source] <Url as FromStr>::Err),
    #[error("must not carry user information")]
    UserInfo,
    #[error("must not carry a query or fragment")]
    QueryOrFragment,
}

/// An HTTP API base URL without user information, a query, or a fragment.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BindizrUrl(Url);

impl FromStr for BindizrUrl {
    type Err = ParseBindizrUrlError;

    /// Validate the upstream URL without retaining untrusted input in errors.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let authority_and_path = value
            .strip_prefix("http://")
            .or_else(|| value.strip_prefix("https://"))
            .ok_or(ParseBindizrUrlError::Scheme)?;
        let url = Url::parse(value).map_err(ParseBindizrUrlError::Invalid)?;

        // HTTP URL parsing skips extra slashes, tabs and newlines before the
        // authority and normalizes an empty user-info delimiter away.
        let authority = authority_and_path
            .trim_start_matches(['/', '\\', '\t', '\n', '\r'])
            .split(['/', '\\', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority.contains('@') || !url.username().is_empty() || url.password().is_some() {
            return Err(ParseBindizrUrlError::UserInfo);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ParseBindizrUrlError::QueryOrFragment);
        }

        Ok(Self(url))
    }
}

impl BindizrUrl {
    /// Append an API path to the configured base URL, retaining its path prefix.
    pub(crate) fn to_request_url(&self, path: &str) -> Url {
        let mut url = self.0.clone();
        url.set_path(&format!("{}{path}", self.0.path().trim_end_matches('/')));
        url
    }

    /// Mask the configured path if an upstream error message echoes it.
    pub(crate) fn redact_path_in(&self, message: String) -> String {
        let path = self.0.path().trim_end_matches('/');
        if path.is_empty() {
            message
        } else {
            message.replace(path, "/<redacted>")
        }
    }
}

impl fmt::Display for BindizrUrl {
    /// Identify the destination without displaying its configured path.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.origin().ascii_serialization())
    }
}

impl fmt::Debug for BindizrUrl {
    /// Identify the destination and omit the configured path in nested Debug.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BindizrUrl")
            .field(&self.0.origin().ascii_serialization())
            .finish()
    }
}

/// ExternalDNS webhook provider adapter for bindizr.
///
/// Serves the ExternalDNS webhook protocol on a localhost listener and
/// forwards every operation to the bindizr HTTP API with a Bearer token.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(name = "bindizr-external-dns", version, about)]
pub(crate) struct Cli {
    /// Base URL of the bindizr HTTP API, e.g. http://bindizr:8000
    #[arg(long, env = "BINDIZR_URL", hide_env_values = true, value_name = "URL")]
    bindizr_url: RedactedString,
    /// Bindizr API token; prefer --token-file so the token stays out of the
    /// process list
    #[arg(long, env = "BINDIZR_API_TOKEN", hide_env_values = true)]
    token: Option<RedactedString>,
    /// File containing the bindizr API token (takes precedence over --token)
    #[arg(long, env = "BINDIZR_API_TOKEN_FILE", value_name = "FILE")]
    token_file: Option<String>,
    /// PEM CA certificate to trust on top of the system roots, for a bindizr
    /// serving a private or self-signed certificate
    #[arg(long, env = "BINDIZR_CA_FILE", value_name = "FILE")]
    ca_file: Option<String>,
    /// Webhook listener address; keep it on localhost so only the
    /// external-dns container in the same pod can reach it
    #[arg(
        long,
        env = "BINDIZR_EXTERNAL_DNS_LISTEN_ADDR",
        default_value = "127.0.0.1:8888"
    )]
    listen_addr: SocketAddr,
    /// Health and metrics listener address, exposed for Kubernetes probes
    #[arg(
        long,
        env = "BINDIZR_EXTERNAL_DNS_HEALTH_ADDR",
        default_value = "0.0.0.0:8080"
    )]
    health_listen_addr: SocketAddr,
    /// Timeout in seconds for each bindizr API request; keep it under the
    /// external-dns webhook write timeout (10s by default) so the mapped
    /// 502 still reaches the caller when bindizr stalls
    #[arg(long, env = "BINDIZR_EXTERNAL_DNS_TIMEOUT_SECS", default_value_t = 8)]
    timeout_secs: u64,
    /// Log level (error, warn, info, debug, trace)
    #[arg(long, env = "BINDIZR_EXTERNAL_DNS_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

/// Why the command line does not describe a runnable adapter.
#[derive(Debug, Error)]
pub(crate) enum LoadAdapterConfigError {
    #[error("invalid --bindizr-url: {0}")]
    Url(#[from] ParseBindizrUrlError),
    #[error("failed to read token file '{path}': {source}")]
    ReadTokenFile {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("invalid --log-level '{value}': {source}")]
    InvalidLogLevel {
        value: String,
        #[source]
        source: ParseConfigValueError,
    },
}

/// The validated adapter settings the listeners and the upstream client start from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterConfig {
    pub(crate) bindizr_url: BindizrUrl,
    pub(crate) token: Option<RedactedString>,
    pub(crate) ca_file: Option<String>,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) health_listen_addr: SocketAddr,
    pub(crate) timeout_secs: u64,
    pub(crate) log_level: LogLevel,
}

impl AdapterConfig {
    /// Validate CLI options and build the adapter configuration.
    pub(crate) fn load(cli: Cli) -> Result<Self, LoadAdapterConfigError> {
        let bindizr_url = cli.bindizr_url.as_str().parse()?;

        let token = match &cli.token_file {
            Some(path) => Some(
                fs::read_to_string(path)
                    .map_err(|source| LoadAdapterConfigError::ReadTokenFile {
                        path: path.clone(),
                        source,
                    })?
                    .trim()
                    .to_string(),
            ),
            None => cli
                .token
                .as_ref()
                .map(|token| token.as_str().trim().to_string()),
        };
        let token = token
            .filter(|token| !token.is_empty())
            .map(RedactedString::from);

        let log_level = cli.log_level.parse::<LogLevel>().map_err(|source| {
            LoadAdapterConfigError::InvalidLogLevel {
                value: cli.log_level.clone(),
                source,
            }
        })?;

        Ok(Self {
            bindizr_url,
            token,
            ca_file: cli.ca_file,
            listen_addr: cli.listen_addr,
            health_listen_addr: cli.health_listen_addr,
            timeout_secs: cli.timeout_secs,
            log_level,
        })
    }
}

#[cfg(test)]
mod tests;
