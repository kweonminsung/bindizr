//! Change provenance shared by zone versions and activity logs.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;
use utoipa::ToSchema;

/// A change-source column holding none of the known sources.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown change source '{value}'")]
pub struct ParseChangeSourceError {
    pub value: String,
}

/// The request path or background process that produced a managed change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ChangeSource {
    /// An HTTP API request, including requests made with authentication disabled.
    Api,
    /// A command received over the daemon's Unix socket.
    Socket,
    /// An RFC 2136 update, signed or unsigned.
    Nsupdate,
    /// Background maintenance, on nobody's request.
    System,
}

impl ChangeSource {
    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Socket => "socket",
            Self::Nsupdate => "nsupdate",
            Self::System => "system",
        }
    }
}

impl fmt::Display for ChangeSource {
    /// Write the change source in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ChangeSource {
    type Err = ParseChangeSourceError;

    /// Parse the stored text of a change source.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "api" => Ok(Self::Api),
            "socket" => Ok(Self::Socket),
            "nsupdate" => Ok(Self::Nsupdate),
            "system" => Ok(Self::System),
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
        value.parse::<Self>()
    }
}

/// An actor's stored columns do not describe a complete, known credential.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum DecodeChangeActorError {
    #[error("change actor kind and name must both be present or both be null")]
    Incomplete,
    #[error("unknown change actor kind '{value}'")]
    UnknownKind { value: String },
}

/// The named credential behind a change, copied so deleting it preserves the history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChangeActor {
    Token { name: String },
    TsigKey { name: String },
}

impl ChangeActor {
    /// Return the kind and name stored in the two actor columns.
    pub fn as_columns(&self) -> (&'static str, &str) {
        match self {
            Self::Token { name } => ("token", name),
            Self::TsigKey { name } => ("tsig_key", name),
        }
    }
}

impl fmt::Display for ChangeActor {
    /// Write the credential kind with its name so equal names remain distinguishable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, name) = self.as_columns();
        write!(f, "{kind}:{name}")
    }
}

/// The nullable SQL columns decoded into one optional actor at the row
/// boundary, by every row that carries an actor.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub(crate) struct ChangeActorColumns {
    actor_kind: Option<String>,
    actor_name: Option<String>,
}

impl TryFrom<ChangeActorColumns> for Option<ChangeActor> {
    type Error = DecodeChangeActorError;

    /// Decode both columns together, rejecting partial or unknown identities.
    fn try_from(columns: ChangeActorColumns) -> Result<Self, Self::Error> {
        match (columns.actor_kind, columns.actor_name) {
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that the scalar columns and API object preserve the same actor kind and name.
    #[test]
    fn actor_columns_match_the_api_identity() {
        for actor in [
            ChangeActor::Token {
                name: "admin".to_string(),
            },
            ChangeActor::TsigKey {
                name: "admin".to_string(),
            },
        ] {
            let (kind, name) = actor.as_columns();

            assert_eq!(
                serde_json::to_value(&actor).unwrap(),
                json!({ "kind": kind, "name": name })
            );
            let decoded = Option::<ChangeActor>::try_from(ChangeActorColumns {
                actor_kind: Some(kind.to_string()),
                actor_name: Some(name.to_string()),
            })
            .unwrap();

            assert_eq!(decoded, Some(actor));
        }
    }

    /// Verify that corrupt column pairs fail decoding instead of dropping or inventing an identity.
    #[test]
    fn actor_columns_decode_only_complete_known_identities() {
        assert_eq!(
            Option::<ChangeActor>::try_from(ChangeActorColumns {
                actor_kind: None,
                actor_name: None,
            })
            .unwrap(),
            None
        );

        for (kind, name, expected) in [
            (Some("token"), None, DecodeChangeActorError::Incomplete),
            (None, Some("admin"), DecodeChangeActorError::Incomplete),
            (
                Some("unknown"),
                Some("admin"),
                DecodeChangeActorError::UnknownKind {
                    value: "unknown".to_string(),
                },
            ),
        ] {
            assert_eq!(
                Option::<ChangeActor>::try_from(ChangeActorColumns {
                    actor_kind: kind.map(str::to_string),
                    actor_name: name.map(str::to_string),
                }),
                Err(expected)
            );
        }
    }

    /// Verify that `ChangeSource` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn change_source_spells_itself_once() {
        for value in [
            ChangeSource::Api,
            ChangeSource::Socket,
            ChangeSource::Nsupdate,
            ChangeSource::System,
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
