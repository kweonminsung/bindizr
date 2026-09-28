//! The latest transfer Bindizr served, refused, or failed for one client and
//! one zone: what a secondary pulled.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use thiserror::Error;

use crate::{
    dns::{Serial, message::Rtype, name::ZoneName},
    model::zone::ZoneId,
};

/// A transfer column holding a kind or result bindizr does not record.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseTransferError {
    #[error("unsupported transfer kind '{0}'")]
    Kind(String),
    #[error("unsupported transfer result '{0}'")]
    Result(String),
}

/// Which transfer a client asked for.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum TransferKind {
    Axfr,
    Ixfr,
}

impl TransferKind {
    /// The transfer a query type asks for; the caller checked it is one.
    pub fn from_qtype(qtype: Rtype) -> Self {
        if qtype == Rtype::IXFR {
            TransferKind::Ixfr
        } else {
            TransferKind::Axfr
        }
    }

    /// Storage name, as the column and the API spell it.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransferKind::Axfr => "axfr",
            TransferKind::Ixfr => "ixfr",
        }
    }
}

impl std::fmt::Display for TransferKind {
    /// Write the transfer kind as the query type name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TransferKind::Axfr => "AXFR",
            TransferKind::Ixfr => "IXFR",
        })
    }
}

impl std::str::FromStr for TransferKind {
    type Err = ParseTransferError;

    /// Parse a transfer kind from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "axfr" => Ok(TransferKind::Axfr),
            "ixfr" => Ok(TransferKind::Ixfr),
            _ => Err(ParseTransferError::Kind(s.to_string())),
        }
    }
}

impl TryFrom<String> for TransferKind {
    type Error = ParseTransferError;

    /// Validate and convert the stored value into a transfer kind.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// How a transfer request turned out: answered, refused by the ACL or the
/// key's grant, or allowed and then broken off by a failure.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum TransferResult {
    Ok,
    Refused,
    Failed,
}

impl TransferResult {
    /// Storage name, as the column and the API spell it.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransferResult::Ok => "ok",
            TransferResult::Refused => "refused",
            TransferResult::Failed => "failed",
        }
    }
}

impl std::fmt::Display for TransferResult {
    /// Write the transfer result as the API spells it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TransferResult {
    type Err = ParseTransferError;

    /// Parse a transfer result from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "ok" => Ok(TransferResult::Ok),
            "refused" => Ok(TransferResult::Refused),
            "failed" => Ok(TransferResult::Failed),
            _ => Err(ParseTransferError::Result(s.to_string())),
        }
    }
}

impl TryFrom<String> for TransferResult {
    type Error = ParseTransferError;

    /// Validate and convert the stored value into a transfer result.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// The latest transfer served to one client address for one zone, as it is
/// written; a refusal or failure keeps its reason and no serial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub client_addr: String,
    pub zone_id: ZoneId,
    /// The transfer the client asked for.
    pub kind: TransferKind,
    pub result: TransferResult,
    /// Whether the answer was a delta; an IXFR the journal could not serve
    /// went out as the whole zone.
    pub incremental: bool,
    /// The serial the answer reached; absent when nothing was transferred.
    pub serial: Option<Serial>,
    pub served_at: DateTime<Utc>,
    /// Why the transfer was refused or failed.
    pub error: Option<String>,
}

/// A transfer joined with its zone's name, as the listings return it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct TransferWithZone {
    pub client_addr: String,
    #[sqlx(try_from = "String")]
    pub kind: TransferKind,
    #[sqlx(try_from = "String")]
    pub result: TransferResult,
    pub incremental: bool,
    pub serial: Option<Serial>,
    pub served_at: DateTime<Utc>,
    pub error: Option<String>,
    #[sqlx(try_from = "String")]
    pub zone_name: ZoneName,
}
