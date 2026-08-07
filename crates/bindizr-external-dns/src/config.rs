//! Adapter configuration from CLI flags and environment variables. The
//! adapter runs next to external-dns, away from the bindizr server, so it
//! deliberately does not read the bindizr configuration file.

use std::net::SocketAddr;

use clap::Parser;

/// ExternalDNS webhook provider adapter for bindizr.
///
/// Serves the ExternalDNS webhook protocol on a localhost listener and
/// forwards every operation to the bindizr HTTP API with a Bearer token.
#[derive(Parser, Debug)]
#[command(name = "bindizr-external-dns", version, about)]
pub(crate) struct Cli {
    /// Base URL of the bindizr HTTP API, e.g. http://bindizr:8000
    #[arg(long, env = "BINDIZR_URL", value_name = "URL")]
    pub bindizr_url: String,

    /// Bindizr API token; prefer --token-file so the token stays out of the
    /// process list
    #[arg(long, env = "BINDIZR_API_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// File containing the bindizr API token (takes precedence over --token)
    #[arg(long, env = "BINDIZR_API_TOKEN_FILE", value_name = "FILE")]
    pub token_file: Option<String>,

    /// Webhook listener address; keep it on localhost so only the
    /// external-dns container in the same pod can reach it
    #[arg(
        long,
        env = "BINDIZR_EXTERNAL_DNS_LISTEN_ADDR",
        default_value = "127.0.0.1:8888"
    )]
    pub listen_addr: SocketAddr,

    /// Health and metrics listener address, exposed for Kubernetes probes
    #[arg(
        long,
        env = "BINDIZR_EXTERNAL_DNS_HEALTH_ADDR",
        default_value = "0.0.0.0:8080"
    )]
    pub health_listen_addr: SocketAddr,

    /// Timeout in seconds for each bindizr API request; keep it under the
    /// external-dns webhook write timeout (10s by default)
    #[arg(long, env = "BINDIZR_EXTERNAL_DNS_TIMEOUT_SECS", default_value_t = 10)]
    pub timeout_secs: u64,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, env = "BINDIZR_EXTERNAL_DNS_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
}

/// Resolved adapter configuration.
#[derive(Debug, Clone)]
pub(crate) struct AdapterConfig {
    /// Normalized base URL without a trailing slash.
    pub bindizr_url: String,
    pub token: Option<String>,
    pub listen_addr: SocketAddr,
    pub health_listen_addr: SocketAddr,
    pub timeout_secs: u64,
    pub log_level: bindizr_core::config::LogLevel,
}

impl AdapterConfig {
    pub fn from_cli(cli: Cli) -> Result<Self, String> {
        let bindizr_url = cli.bindizr_url.trim().trim_end_matches('/').to_string();
        if !bindizr_url.starts_with("http://") && !bindizr_url.starts_with("https://") {
            return Err(format!(
                "--bindizr-url must start with http:// or https://, got '{}'",
                bindizr_url
            ));
        }

        let token = match &cli.token_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read token file '{}': {}", path, e))?
                    .trim()
                    .to_string(),
            ),
            None => cli.token.as_deref().map(|t| t.trim().to_string()),
        };
        let token = token.filter(|t| !t.is_empty());

        let log_level = cli
            .log_level
            .parse::<bindizr_core::config::LogLevel>()
            .map_err(|e| format!("Invalid --log-level '{}': {}", cli.log_level, e))?;

        Ok(AdapterConfig {
            bindizr_url,
            token,
            listen_addr: cli.listen_addr,
            health_listen_addr: cli.health_listen_addr,
            timeout_secs: cli.timeout_secs,
            log_level,
        })
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{AdapterConfig, Cli};

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("bindizr-external-dns").chain(args.iter().copied()))
            .unwrap()
    }

    #[test]
    fn listener_defaults_to_localhost_only() {
        let cli = parse(&["--bindizr-url", "http://bindizr:8000"]);
        assert_eq!(cli.listen_addr.to_string(), "127.0.0.1:8888");
        assert_eq!(cli.health_listen_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(cli.timeout_secs, 10);
    }

    #[test]
    fn config_normalizes_url_and_requires_http_scheme() {
        let config =
            AdapterConfig::from_cli(parse(&["--bindizr-url", "http://bindizr:8000/"])).unwrap();
        assert_eq!(config.bindizr_url, "http://bindizr:8000");
        assert!(config.token.is_none());

        assert!(AdapterConfig::from_cli(parse(&["--bindizr-url", "bindizr:8000"])).is_err());
    }

    #[test]
    fn token_file_takes_precedence_and_is_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "secret-token\n").unwrap();

        let config = AdapterConfig::from_cli(parse(&[
            "--bindizr-url",
            "http://bindizr:8000",
            "--token",
            "inline-token",
            "--token-file",
            path.to_str().unwrap(),
        ]))
        .unwrap();

        assert_eq!(config.token.as_deref(), Some("secret-token"));
    }

    #[test]
    fn missing_token_resolves_to_none() {
        let config = AdapterConfig::from_cli(parse(&[
            "--bindizr-url",
            "http://bindizr:8000",
            "--token",
            "",
        ]))
        .unwrap();
        assert!(config.token.is_none());
    }
}
