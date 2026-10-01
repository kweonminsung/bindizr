use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

use crate::{
    dns::{Serial, SoaInterval, Ttl},
    model::zone::ZoneId,
};

/// Select stored versions by journal content, independently of who made the change.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionFilter {
    /// Exclude past versions with nonempty journals containing only derived DNSSEC changes.
    /// Keep the current version and versions without journal entries.
    ExcludePastSignerOnly,
    /// Include every stored version, including past signer-only versions.
    All,
}

impl VersionFilter {
    /// Select the history filter requested by `include_signer_serials`.
    pub fn from_include_signer_serials(include_signer_serials: bool) -> Self {
        if include_signer_serials {
            VersionFilter::All
        } else {
            VersionFilter::ExcludePastSignerOnly
        }
    }
}

id_newtype!(
    /// The id of a zone version row.
    ZoneVersionId
);

/// Point-in-time version of a zone's SOA fields at a given serial.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ZoneVersion {
    pub id: ZoneVersionId,
    pub zone_id: ZoneId,
    pub serial: Serial,
    pub mname: String,
    /// Stored in SOA mailbox encoded form, unlike `Zone.rname` which holds the
    /// admin email.
    pub rname: String,
    pub default_ttl: Ttl,
    pub refresh: SoaInterval,
    pub retry: SoaInterval,
    pub expire: SoaInterval,
    pub minimum_ttl: Ttl,
    /// The request path or background process that produced this version.
    #[sqlx(try_from = "String")]
    pub change_source: ChangeSource,
    /// A snapshot of the token or TSIG key identity, independent of the request path.
    #[sqlx(flatten, try_from = "ChangeActorColumns")]
    pub changed_by: Option<ChangeActor>,
    pub created_at: DateTime<Utc>,
}

/// A change-source column holding none of the known sources.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown change source '{value}'")]
pub struct ParseChangeSourceError {
    pub value: String,
}

/// The request path or background process that produced a zone version.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ChangeSource {
    /// An HTTP API request, including requests made with authentication disabled.
    Api,
    /// A command received over the daemon's Unix socket.
    Socket,
    /// An RFC 2136 update, signed or unsigned.
    Nsupdate,
    /// The DNSSEC scheduler, on nobody's request.
    System,
}

impl ChangeSource {
    /// Return the text representation of this change source.
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeSource::Api => "api",
            ChangeSource::Socket => "socket",
            ChangeSource::Nsupdate => "nsupdate",
            ChangeSource::System => "system",
        }
    }
}

impl std::fmt::Display for ChangeSource {
    /// Write the change source in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ChangeSource {
    type Err = ParseChangeSourceError;

    /// Parse the stored text of a change source.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "api" => Ok(ChangeSource::Api),
            "socket" => Ok(ChangeSource::Socket),
            "nsupdate" => Ok(ChangeSource::Nsupdate),
            "system" => Ok(ChangeSource::System),
            other => Err(ParseChangeSourceError {
                value: other.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for ChangeSource {
    type Error = ParseChangeSourceError;

    /// Validate and convert the stored value into a change source.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// The named credential behind a change, copied so deleting it preserves the history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChangeActor {
    Token { name: String },
    TsigKey { name: String },
}

impl ChangeActor {
    /// Borrow the kind and name stored in the two attribution columns.
    pub fn as_columns(&self) -> (&'static str, &str) {
        match self {
            ChangeActor::Token { name } => ("token", name),
            ChangeActor::TsigKey { name } => ("tsig_key", name),
        }
    }
}

/// The nullable SQL columns decoded into one optional actor at the row boundary.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
struct ChangeActorColumns {
    changed_by_kind: Option<String>,
    changed_by_name: Option<String>,
}

/// An actor's stored columns do not describe a complete, known credential.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum DecodeChangeActorError {
    #[error("change actor kind and name must both be present or both be null")]
    Incomplete,
    #[error("unknown change actor kind '{value}'")]
    UnknownKind { value: String },
}

impl TryFrom<ChangeActorColumns> for Option<ChangeActor> {
    type Error = DecodeChangeActorError;

    /// Decode both columns together, rejecting partial or unknown identities.
    fn try_from(columns: ChangeActorColumns) -> Result<Self, Self::Error> {
        match (columns.changed_by_kind, columns.changed_by_name) {
            (None, None) => Ok(None),
            (Some(kind), Some(name)) => match kind.as_str() {
                "token" => Ok(Some(ChangeActor::Token { name })),
                "tsig_key" => Ok(Some(ChangeActor::TsigKey { name })),
                _ => Err(DecodeChangeActorError::UnknownKind { value: kind }),
            },
            _ => Err(DecodeChangeActorError::Incomplete),
        }
    }
}

impl std::fmt::Display for ChangeActor {
    /// Show the credential kind with its name so equal names remain distinguishable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, name) = self.as_columns();
        write!(f, "{kind}:{name}")
    }
}

#[cfg(test)]
mod tests;

impl VersionFilter {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExcludePastSignerOnly => "exclude_past_signer_only",
            Self::All => "all",
        }
    }
}

impl serde::Serialize for VersionFilter {
    /// Serialize through the canonical spelling used by the wire contract.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
