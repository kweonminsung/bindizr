use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::FromRow;

use crate::dns::{Serial, SoaInterval, Ttl};
use crate::model::change::{ChangeActor, ChangeActorColumns, ChangeSource};
use crate::model::zone::ZoneId;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the canonical spelling and round-trip of every VersionFilter variant.
    #[test]
    fn version_filter_spells_itself_once() {
        for (value, expected) in [
            (
                VersionFilter::ExcludePastSignerOnly,
                "exclude_past_signer_only",
            ),
            (VersionFilter::All, "all"),
        ] {
            assert_eq!(value.as_str(), expected);
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(expected)
            );
            assert_eq!(
                serde_json::from_value::<VersionFilter>(serde_json::json!(expected)).unwrap(),
                value
            );
        }
    }
}
