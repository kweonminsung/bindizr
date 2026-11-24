//! Authenticated HTTP client for the bindizr `/external-dns` API.

use std::borrow::Cow;
use std::time::Duration;
use std::{fmt, fs, io};

use reqwest::{Certificate, Client, Method, RequestBuilder, Response, StatusCode};
use rustls::crypto::ring;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{BindizrUrl, RedactedString};
use crate::wire::{ApplyExternalDnsChangesRequest, BindizrRecord};

/// A reqwest failure with its request URL removed before it leaves the client.
#[derive(Error)]
#[error("{0}")]
pub(crate) struct HttpClientError(#[source] reqwest::Error);

impl From<reqwest::Error> for HttpClientError {
    /// Retain the typed cause without its URL.
    fn from(error: reqwest::Error) -> Self {
        Self(error.without_url())
    }
}

impl fmt::Debug for HttpClientError {
    /// Format the sanitized error without printing arbitrary nested client diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HttpClientError")
            .field(&self.0.to_string())
            .finish()
    }
}

/// A bindizr API failure, split for the webhook error mapping in `server`.
#[derive(Debug, Error)]
pub(crate) enum UpstreamError {
    /// The error body bindizr answered with, under its status.
    #[error("{message}")]
    Rejected { status: StatusCode, message: String },
    /// Connect error or timeout.
    #[error("bindizr is unreachable: {0}")]
    Unreachable(#[source] HttpClientError),
    /// bindizr answered something that was not the payload asked for.
    #[error("invalid response from bindizr: {0}")]
    InvalidResponse(#[source] HttpClientError),
}

/// Why the client to bindizr could not be built.
#[derive(Debug, Error)]
pub(crate) enum BuildClientError {
    #[error("failed to read the CA certificate '{path}': {source}")]
    ReadCa {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("invalid CA certificate '{path}': {source}")]
    InvalidCa {
        path: String,
        #[source]
        source: HttpClientError,
    },
    #[error("failed to build HTTP client: {0}")]
    Build(#[source] HttpClientError),
}

/// The `error` message a bindizr API error response carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UpstreamErrorResponse {
    error: String,
}

/// HTTP client for the bindizr `/external-dns` API, sending the Bearer token
/// with every request.
pub(crate) struct UpstreamClient {
    http: Client,
    base_url: BindizrUrl,
    token: Option<RedactedString>,
}

impl fmt::Debug for UpstreamClient {
    /// Redact the token and omit reqwest's proxy and header diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamClient")
            .field("base_url", &self.base_url)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

impl UpstreamClient {
    /// Build the bindizr HTTP client with authentication, timeout, and TLS settings.
    pub(crate) fn new(
        base_url: BindizrUrl,
        token: Option<RedactedString>,
        timeout_secs: u64,
        ca_file: Option<&str>,
    ) -> Result<Self, BuildClientError> {
        // reqwest builds no rustls client without a process-level provider;
        // Err means one is installed already.
        let _ = ring::default_provider().install_default();
        let mut builder = Client::builder().timeout(Duration::from_secs(timeout_secs));

        // Added to the system roots rather than replacing them, so one private
        // CA does not cut off a publicly issued certificate beside it.
        if let Some(path) = ca_file {
            let pem = fs::read(path).map_err(|source| BuildClientError::ReadCa {
                path: path.to_string(),
                source,
            })?;

            for certificate in Certificate::from_pem_bundle(&pem).map_err(|source| {
                BuildClientError::InvalidCa {
                    path: path.to_string(),
                    source: source.into(),
                }
            })? {
                builder = builder.add_root_certificate(certificate);
            }
        }

        let http = builder
            .build()
            .map_err(|error| BuildClientError::Build(error.into()))?;

        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    /// Fetch domain names available to the adapter's token.
    pub(crate) async fn list_domains(&self) -> Result<Vec<String>, UpstreamError> {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct ListExternalDnsDomainsResponse {
            domains: Vec<String>,
        }
        let body: ListExternalDnsDomainsResponse = self.fetch_json("/external-dns/domains").await?;
        Ok(body.domains)
    }

    /// Fetch the records visible through the bindizr external-dns API.
    pub(crate) async fn list_records(&self) -> Result<Vec<BindizrRecord>, UpstreamError> {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct ListExternalDnsRecordsResponse {
            records: Vec<BindizrRecord>,
        }
        let body: ListExternalDnsRecordsResponse = self.fetch_json("/external-dns/records").await?;
        Ok(body.records)
    }

    /// Submit a record change set to the bindizr API.
    pub(crate) async fn apply_changes(
        &self,
        changes: &ApplyExternalDnsChangesRequest,
    ) -> Result<(), UpstreamError> {
        let request = self
            .build_request(Method::POST, "/external-dns/changes")
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
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct AdjustExternalDnsRecordsRequest<'a> {
            records: Cow<'a, [BindizrRecord]>,
        }
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct AdjustExternalDnsRecordsResponse {
            records: Vec<BindizrRecord>,
        }
        let request = self
            .build_request(Method::POST, "/external-dns/adjust")
            .json(&AdjustExternalDnsRecordsRequest {
                records: records.into(),
            });

        let response = self.send(request).await?;
        let body: AdjustExternalDnsRecordsResponse = response
            .json()
            .await
            .map_err(|error| UpstreamError::InvalidResponse(error.into()))?;

        Ok(body.records)
    }

    /// Fetch and deserialize a JSON response from a bindizr API path.
    async fn fetch_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, UpstreamError> {
        let response = self.send(self.build_request(Method::GET, path)).await?;

        response
            .json::<T>()
            .await
            .map_err(|error| UpstreamError::InvalidResponse(error.into()))
    }

    /// Build an authenticated request to a bindizr API path.
    fn build_request(&self, method: Method, path: &str) -> RequestBuilder {
        let mut request = self
            .http
            .request(method, self.base_url.to_request_url(path));

        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_str());
        }

        request
    }

    /// Send an upstream request and translate transport or HTTP failures.
    async fn send(&self, request: RequestBuilder) -> Result<Response, UpstreamError> {
        let response = request
            .send()
            .await
            .map_err(|error| UpstreamError::Unreachable(error.into()))?;

        let status = response.status();

        if status.is_success() {
            return Ok(response);
        }

        // Preserve validation diagnostics while masking reflected credentials.
        let response_url = response.url().clone();
        let message = response.json::<UpstreamErrorResponse>().await.map_or_else(
            |_| format!("bindizr responded with status {}", status.as_u16()),
            |body| {
                let message = body.error.replace(
                    response_url.as_str(),
                    &response_url.origin().ascii_serialization(),
                );
                let message = self.base_url.redact_path_in(message);
                if let Some(token) = &self.token
                    && !token.as_str().is_empty()
                {
                    message.replace(token.as_str(), "<redacted>")
                } else {
                    message
                }
            },
        );

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            log::error!(
                "bindizr rejected the request with {} ({message}); check the API token and its grants",
                status.as_u16()
            );
        }

        Err(UpstreamError::Rejected { status, message })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use tokio::net::TcpListener;

    use super::*;

    /// Verify that the client and its transport failures format without credentials.
    #[tokio::test]
    async fn client_diagnostics_omit_request_url_and_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = UpstreamClient::new(
            format!("http://{addr}/dummy-path-secret").parse().unwrap(),
            Some("dummy-api-token".to_string().into()),
            2,
            None,
        )
        .unwrap();
        let error = client.list_domains().await.unwrap_err();
        let UpstreamError::Unreachable(http_error) = &error else {
            panic!("expected a transport failure: {error}");
        };
        let source = http_error.source().unwrap();
        let source = source.downcast_ref::<reqwest::Error>().unwrap();
        assert!(source.url().is_none());

        let diagnostics = format!("{client:?} {client:#?} {error} {error:?} {error:#?} {source:?}");
        assert!(diagnostics.contains("bindizr is unreachable"));
        assert!(!diagnostics.contains("dummy-path-secret"));
        assert!(!diagnostics.contains("dummy-api-token"));
    }
}
