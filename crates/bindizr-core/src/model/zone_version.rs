use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

use crate::{
    dns::{Serial, SoaInterval, Ttl},
    model::zone::ZoneId,
};

/// Select stored versions by journal content, independently of who made the change.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Which plane asked for this version.
    #[sqlx(try_from = "String")]
    pub change_source: ChangeSource,
    /// The API token or TSIG key the change was made under, absent where no
    /// credential stood behind it. Copied rather than referenced, so the
    /// answer outlives the credential.
    pub changed_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A change-source column holding none of the known sources.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown change source '{value}'")]
pub struct ParseChangeSourceError {
    pub value: String,
}

/// The plane a zone version's change came through.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ChangeSource {
    /// An API token, global or scoped.
    Token,
    /// An RFC 2136 update, named by the TSIG key that signed it.
    Nsupdate,
    /// The DNSSEC scheduler, on nobody's request.
    System,
    /// No credential stood behind it: the daemon socket, or any request made
    /// while authentication is disabled.
    Local,
}

impl ChangeSource {
    /// Return the text representation of this change source.
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeSource::Token => "token",
            ChangeSource::Nsupdate => "nsupdate",
            ChangeSource::System => "system",
            ChangeSource::Local => "local",
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
            "token" => Ok(ChangeSource::Token),
            "nsupdate" => Ok(ChangeSource::Nsupdate),
            "system" => Ok(ChangeSource::System),
            "local" => Ok(ChangeSource::Local),
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that `ChangeSource` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn change_source_spells_itself_once() {
        for value in [
            ChangeSource::Token,
            ChangeSource::Nsupdate,
            ChangeSource::System,
            ChangeSource::Local,
        ] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<ChangeSource>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<ChangeSource>().unwrap(), value);
        }
    }
}
