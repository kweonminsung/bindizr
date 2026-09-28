//! Authenticated HTTP client for the bindizr `/external-dns` API.

use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::wire::{BindizrChanges, BindizrRecord};

/// A bindizr API failure, split for the webhook error mapping in `server`.
#[derive(Debug, Error)]
pub(crate) enum UpstreamError {
    /// The error body bindizr answered with, under its status.
    #[error("{message}")]
    Rejected { status: u16, message: String },
    /// Connect error or timeout.
    #[error("bindizr is unreachable: {0}")]
    Unreachable(#[source] reqwest::Error),
    /// bindizr answered something that was not the payload asked for.
    #[error("invalid response from bindizr: {0}")]
    InvalidResponse(#[source] reqwest::Error),
    /// bindizr answered, but the token reaches no zone this adapter could manage.
    #[error("no manageable names")]
    NoManageableNames,
}

/// Why the client to bindizr could not be built.
#[derive(Debug, Error)]
pub(crate) enum BuildClientError {
    #[error("Failed to read the CA certificate '{path}': {source}")]
    ReadCa {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Invalid CA certificate '{path}': {source}")]
    InvalidCa {
        path: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("Failed to build HTTP client: {0}")]
    Build(#[source] reqwest::Error),
}

/// The `error` message a bindizr API error response carries.
#[derive(Deserialize)]
struct UpstreamErrorBody {
    error: String,
}

/// HTTP client for the bindizr `/external-dns` API, sending the Bearer token
/// with every request.
#[derive(Debug)]
pub(crate) struct UpstreamClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<String>,
}

impl UpstreamClient {
    /// Build the bindizr HTTP client with authentication, timeout, and TLS settings.
    pub(crate) fn new(
        base_url: String,
        token: Option<String>,
        timeout_secs: u64,
        ca_file: Option<&str>,
    ) -> Result<Self, BuildClientError> {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(timeout_secs));
        // Added to the system roots rather than replacing them, so one private
        // CA does not cut off a publicly issued certificate beside it.
        if let Some(path) = ca_file {
            let pem = std::fs::read(path).map_err(|source| BuildClientError::ReadCa {
                path: path.to_string(),
                source,
            })?;
            for certificate in reqwest::Certificate::from_pem_bundle(&pem).map_err(|source| {
                BuildClientError::InvalidCa {
                    path: path.to_string(),
                    source,
                }
            })? {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let http = builder.build().map_err(BuildClientError::Build)?;
        Ok(UpstreamClient {
            http,
            base_url,
            token,
        })
    }

    /// Fetch domain names available to the adapter's token.
    pub(crate) async fn list_domains(&self) -> Result<Vec<String>, UpstreamError> {
        #[derive(Deserialize)]
        struct DomainsBody {
            domains: Vec<String>,
        }
        let body: DomainsBody = self.fetch_json("/external-dns/domains").await?;
        Ok(body.domains)
    }

    /// Fetch the records visible through the bindizr external-dns API.
    pub(crate) async fn list_records(&self) -> Result<Vec<BindizrRecord>, UpstreamError> {
        #[derive(Deserialize)]
        struct RecordsBody {
            records: Vec<BindizrRecord>,
        }
        let body: RecordsBody = self.fetch_json("/external-dns/records").await?;
        Ok(body.records)
    }

    /// Submit a record change set to the bindizr API.
    pub(crate) async fn apply_changes(
        &self,
        changes: &BindizrChanges,
    ) -> Result<(), UpstreamError> {
        let request = self
            .request(reqwest::Method::POST, "/external-dns/changes")
            .json(changes);
        self.send(request).await?;
        Ok(())
    }

    /// Canonicalize desired records on the bindizr server; the response
    /// pairs with the request by position.
    pub(crate) async fn adjust_records(
        &self,
        records: &[BindizrRecord],
    ) -> Result<Vec<BindizrRecord>, UpstreamError> {
        #[derive(serde::Serialize)]
        struct AdjustRequest<'a> {
            records: &'a [BindizrRecord],
        }
        #[derive(Deserialize)]
        struct AdjustBody {
            records: Vec<BindizrRecord>,
        }
        let request = self
            .request(reqwest::Method::POST, "/external-dns/adjust")
            .json(&AdjustRequest { records });
        let response = self.send(request).await?;
        let body: AdjustBody = response
            .json()
            .await
            .map_err(UpstreamError::InvalidResponse)?;
        Ok(body.records)
    }

    /// Probe whether the adapter can work at all: bindizr answers, accepts this
    /// token, and grants it something to manage. The unauthenticated `/health`
    /// stays green through a token rotated away or never granted a zone.
    pub(crate) async fn probe_health(&self) -> Result<(), UpstreamError> {
        match self.list_domains().await?.is_empty() {
            true => Err(UpstreamError::NoManageableNames),
            false => Ok(()),
        }
    }

    /// Fetch and deserialize a JSON response from a bindizr API path.
    async fn fetch_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, UpstreamError> {
        let response = self.send(self.request(reqwest::Method::GET, path)).await?;
        response
            .json::<T>()
            .await
            .map_err(UpstreamError::InvalidResponse)
    }

    /// Build an authenticated request to a bindizr API path.
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base_url, path));
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        request
    }

    /// Send an upstream request and translate transport or HTTP failures.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, UpstreamError> {
        let response = request.send().await.map_err(UpstreamError::Unreachable)?;

        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        // Surface the bindizr error body's message; never the token.
        let message = response
            .json::<UpstreamErrorBody>()
            .await
            .map(|body| body.error)
            .unwrap_or_else(|_| format!("bindizr responded with status {}", status.as_u16()));

        if status.as_u16() == 401 || status.as_u16() == 403 {
            log::error!(
                "bindizr rejected the request with {} ({}); check the API token and its grants",
                status.as_u16(),
                message
            );
        }

        Err(UpstreamError::Rejected {
            status: status.as_u16(),
            message,
        })
    }
}
