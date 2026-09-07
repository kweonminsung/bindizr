//! Authenticated HTTP client for the bindizr `/external-dns` API.

use std::time::Duration;

use bindizr_core::log_error;
use serde::Deserialize;

use crate::wire::{BindizrChanges, BindizrRecord};

/// A bindizr API failure, split for the webhook error mapping in `server`.
#[derive(Debug)]
pub(crate) enum UpstreamError {
    Status {
        status: u16,
        message: String,
    },
    /// Connect error or timeout.
    Unreachable(String),
}

#[derive(Deserialize)]
struct UpstreamErrorBody {
    error: String,
}

pub(crate) struct UpstreamClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<String>,
}

impl UpstreamClient {
    pub(crate) fn new(
        base_url: String,
        token: Option<String>,
        timeout_secs: u64,
    ) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
        Ok(UpstreamClient {
            http,
            base_url,
            token,
        })
    }

    pub(crate) async fn list_zones(&self) -> Result<Vec<String>, UpstreamError> {
        #[derive(Deserialize)]
        struct ZonesBody {
            zones: Vec<String>,
        }
        let body: ZonesBody = self.fetch_json("/external-dns/zones").await?;
        Ok(body.zones)
    }

    pub(crate) async fn list_records(&self) -> Result<Vec<BindizrRecord>, UpstreamError> {
        #[derive(Deserialize)]
        struct RecordsBody {
            records: Vec<BindizrRecord>,
        }
        let body: RecordsBody = self.fetch_json("/external-dns/records").await?;
        Ok(body.records)
    }

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
        let body: AdjustBody = response.json().await.map_err(|e| {
            UpstreamError::Unreachable(format!("invalid response from bindizr: {}", e))
        })?;
        Ok(body.records)
    }

    /// Unauthenticated liveness probe of the bindizr server.
    pub(crate) async fn probe_health(&self) -> Result<(), UpstreamError> {
        let request = self.http.get(format!("{}/health", self.base_url));
        self.send(request).await?;
        Ok(())
    }

    async fn fetch_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, UpstreamError> {
        let response = self.send(self.request(reqwest::Method::GET, path)).await?;
        response.json::<T>().await.map_err(|e| {
            UpstreamError::Unreachable(format!("invalid response from bindizr: {}", e))
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base_url, path));
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        request
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, UpstreamError> {
        let response = request
            .send()
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("bindizr is unreachable: {}", e)))?;

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
            log_error!(
                "bindizr rejected the request with {} ({}); check the API token and its grants",
                status.as_u16(),
                message
            );
        }

        Err(UpstreamError::Status {
            status: status.as_u16(),
            message,
        })
    }
}
