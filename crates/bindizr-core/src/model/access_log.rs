//! The access log: every management API request and nsupdate Bindizr
//! answered, who made it, and how it ended.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;
use utoipa::ToSchema;

use crate::model::change::{ChangeActor, ChangeActorColumns};

/// An access column holding a source or result bindizr does not record.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseAccessLogError {
    #[error("unsupported access source '{value}' (supported: api, nsupdate)")]
    Source { value: String },
    #[error("unsupported access result '{value}' (supported: ok, denied, failed)")]
    Result { value: String },
}

/// The front end a request arrived at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AccessSource {
    /// An HTTP API request, including requests made with authentication disabled.
    Api,
    /// An RFC 2136 update, signed or unsigned.
    Nsupdate,
}

impl AccessSource {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Nsupdate => "nsupdate",
        }
    }
}

impl fmt::Display for AccessSource {
    /// Write the source in its storage form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AccessSource {
    type Err = ParseAccessLogError;

    /// Parse a source from its storage form, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "api" => Ok(Self::Api),
            "nsupdate" => Ok(Self::Nsupdate),
            _ => Err(ParseAccessLogError::Source {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for AccessSource {
    type Error = ParseAccessLogError;

    /// Validate and convert the stored value into a source.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse::<Self>()
    }
}

/// How a request ended: answered, denied by authentication or authorization,
/// or failed for any other reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AccessResult {
    Ok,
    /// HTTP 401 or 403; an nsupdate whose TSIG was rejected or that was REFUSED.
    Denied,
    /// Any other error; a zone the caller may not see answers 404 and lands here,
    /// so a scope cannot probe existence through the log either.
    Failed,
}

impl AccessResult {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for AccessResult {
    /// Write the result in its storage form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AccessResult {
    type Err = ParseAccessLogError;

    /// Parse a result from its storage form, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "ok" => Ok(Self::Ok),
            "denied" => Ok(Self::Denied),
            "failed" => Ok(Self::Failed),
            _ => Err(ParseAccessLogError::Result {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for AccessResult {
    type Error = ParseAccessLogError;

    /// Validate and convert the stored value into a result.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse::<Self>()
    }
}

/// One request a front end answered. Nothing secret is kept: no token, key,
/// query string or body, only what the request named and how it ended.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AccessLog {
    #[sqlx(try_from = "String")]
    pub source: AccessSource,
    /// The connection's peer address; a proxy in front shows as itself.
    pub client_addr: String,
    /// The HTTP method, or `UPDATE` for an nsupdate.
    pub method: String,
    /// The request path without its query, or the zone an nsupdate named.
    pub target: String,
    /// The HTTP status code, or the DNS RCODE mnemonic.
    pub status: String,
    #[sqlx(try_from = "String")]
    pub result: AccessResult,
    /// The token or TSIG key the request authenticated with; none when it
    /// presented none, or what it presented did not verify.
    #[sqlx(flatten, try_from = "ChangeActorColumns")]
    pub caller: Option<ChangeActor>,
    /// The error the request was answered with.
    pub error: Option<String>,
    pub requested_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that `AccessSource` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn access_source_spells_itself_once() {
        for value in [AccessSource::Api, AccessSource::Nsupdate] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<AccessSource>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<AccessSource>().unwrap(), value);
        }

        assert!("socket".parse::<AccessSource>().is_err());
    }

    /// Verify that `AccessResult` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn access_result_spells_itself_once() {
        for value in [AccessResult::Ok, AccessResult::Denied, AccessResult::Failed] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<AccessResult>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<AccessResult>().unwrap(), value);
        }

        assert!("refused".parse::<AccessResult>().is_err());
    }
}
