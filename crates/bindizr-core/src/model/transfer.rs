//! The transfer log: every transfer Bindizr served, refused, or failed for a
//! client address and a zone, which is what a secondary pulled.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use domain::base::iana::Rtype;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;
use utoipa::ToSchema;

use crate::dns::name::ZoneName;
use crate::dns::{DnsTransport, Serial};
use crate::model::zone::ZoneId;

/// A transfer query or column holding a value bindizr does not support.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseTransferError {
    #[error("unsupported transfer kind '{value}'")]
    Kind { value: String },
    #[error("unsupported transfer query type '{value}'")]
    QueryType { value: Rtype },
    #[error("unsupported transfer result '{value}' (supported: {})", TransferResult::supported_names().join(", "))]
    Result { value: String },
}

/// Which transfer a client asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransferKind {
    Axfr,
    Ixfr,
}

impl TransferKind {
    /// Every kind, as the metrics pre-register them.
    pub const ALL: [Self; 2] = [Self::Axfr, Self::Ixfr];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Axfr => "axfr",
            Self::Ixfr => "ixfr",
        }
    }
}

impl fmt::Display for TransferKind {
    /// Write the transfer kind as the query type name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Axfr => "AXFR",
            Self::Ixfr => "IXFR",
        })
    }
}

impl FromStr for TransferKind {
    type Err = ParseTransferError;

    /// Parse a transfer kind from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "axfr" => Ok(Self::Axfr),
            "ixfr" => Ok(Self::Ixfr),
            _ => Err(ParseTransferError::Kind {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for TransferKind {
    type Error = ParseTransferError;

    /// Validate and convert the stored value into a transfer kind.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse::<Self>()
    }
}

impl TryFrom<Rtype> for TransferKind {
    type Error = ParseTransferError;

    /// Convert a wire question type to a supported transfer kind.
    fn try_from(value: Rtype) -> Result<Self, Self::Error> {
        match value {
            Rtype::AXFR => Ok(Self::Axfr),
            Rtype::IXFR => Ok(Self::Ixfr),
            _ => Err(ParseTransferError::QueryType { value }),
        }
    }
}

/// How a transfer request turned out: answered, refused by the ACL or the
/// key's grant, or allowed and then broken off by a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransferResult {
    Ok,
    Refused,
    Failed,
}

impl TransferResult {
    /// Every TransferResult value, in declaration order.
    pub const ALL: [Self; 3] = [Self::Ok, Self::Refused, Self::Failed];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }

    /// List the names a value parses from, for messages that list them.
    pub fn supported_names() -> Vec<&'static str> {
        Self::ALL.into_iter().map(Self::as_str).collect()
    }
}

impl fmt::Display for TransferResult {
    /// Write the transfer result as the API spells it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TransferResult {
    type Err = ParseTransferError;

    /// Parse a transfer result from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "ok" => Ok(Self::Ok),
            "refused" => Ok(Self::Refused),
            "failed" => Ok(Self::Failed),
            _ => Err(ParseTransferError::Result {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for TransferResult {
    type Error = ParseTransferError;

    /// Validate and convert the stored value into a transfer result.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse::<Self>()
    }
}

/// One transfer answered to a client address for a zone, as it is written; a
/// refusal or failure keeps a fixed error classification and no serial.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct TransferLog {
    pub client_ip: String,
    pub zone_id: ZoneId,
    /// The transfer the client asked for.
    #[sqlx(try_from = "String")]
    pub kind: TransferKind,
    #[sqlx(try_from = "String")]
    pub result: TransferResult,
    /// Plain TCP or TLS; a transfer never completes over UDP.
    #[sqlx(try_from = "String")]
    pub transport: DnsTransport,
    /// Whether the answer was a delta; an IXFR the journal could not serve
    /// went out as the whole zone.
    pub incremental: bool,
    /// The serial the answer reached; absent when nothing was transferred.
    pub serial: Option<Serial>,
    pub created_at: DateTime<Utc>,
    /// A fixed failure classification without record values or detailed diagnostics.
    pub error_code: Option<String>,
}

/// A transfer log row joined with its zone's name, as the listings return it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct TransferLogWithZone {
    #[sqlx(flatten)]
    pub log: TransferLog,
    pub zone_name: ZoneName,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that only transfer question types map to a transfer kind.
    #[test]
    fn transfer_kind_checks_the_wire_type() {
        assert_eq!(TransferKind::try_from(Rtype::AXFR), Ok(TransferKind::Axfr));
        assert_eq!(TransferKind::try_from(Rtype::IXFR), Ok(TransferKind::Ixfr));
        assert_eq!(
            TransferKind::try_from(Rtype::SOA),
            Err(ParseTransferError::QueryType { value: Rtype::SOA })
        );
    }

    /// Verify that `TransferKind` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn transfer_kind_spells_itself_once() {
        for value in [TransferKind::Axfr, TransferKind::Ixfr] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<TransferKind>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<TransferKind>().unwrap(), value);
        }
    }

    /// Verify that `TransferResult` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn transfer_result_spells_itself_once() {
        for value in [
            TransferResult::Ok,
            TransferResult::Refused,
            TransferResult::Failed,
        ] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<TransferResult>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<TransferResult>().unwrap(), value);
        }
    }
}
