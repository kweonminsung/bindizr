//! One management change, kept so who changed what, and when, can be read
//! back: the trace a zone version leaves for zone data, for everything a
//! version does not record.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use thiserror::Error;

use crate::model::zone_version::{ChangeActor, ChangeActorColumns, ChangeSource};

id_newtype!(
    /// The id of an audit log row.
    AuditLogId
);

/// An audit column holding an entity or operation bindizr does not record.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseAuditLogError {
    #[error("unsupported audit entity '{value}' (supported: {})", AuditEntity::supported_names().join(", "))]
    Entity { value: String },
    #[error("unsupported audit operation '{value}'")]
    Operation { value: String },
}

/// What a management change was made to.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuditEntity {
    Token,
    Role,
    /// A grant of a role; the row's name is the role's.
    RoleGrant,
    TsigKey,
    Secondary,
    DnssecPolicy,
    /// A zone's deletion, since its versions go with it; its other changes
    /// are versioned.
    Zone,
}

impl AuditEntity {
    /// Every entity, in storage order.
    pub const ALL: [Self; 7] = [
        Self::Token,
        Self::Role,
        Self::RoleGrant,
        Self::TsigKey,
        Self::Secondary,
        Self::DnssecPolicy,
        Self::Zone,
    ];

    /// Storage and API form.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditEntity::Token => "token",
            AuditEntity::Role => "role",
            AuditEntity::RoleGrant => "role_grant",
            AuditEntity::TsigKey => "tsig_key",
            AuditEntity::Secondary => "secondary",
            AuditEntity::DnssecPolicy => "dnssec_policy",
            AuditEntity::Zone => "zone",
        }
    }

    /// The names an entity parses from, for messages that list them.
    pub fn supported_names() -> Vec<&'static str> {
        Self::ALL.iter().map(|entity| entity.as_str()).collect()
    }
}

impl std::fmt::Display for AuditEntity {
    /// Write the entity in its storage form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AuditEntity {
    type Err = ParseAuditLogError;

    /// Parse an entity from its storage form, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|entity| entity.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| ParseAuditLogError::Entity {
                value: value.to_string(),
            })
    }
}

impl TryFrom<String> for AuditEntity {
    type Error = ParseAuditLogError;

    /// Validate and convert the stored value into an entity.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// What was done to the entity.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum AuditOperation {
    Create,
    Update,
    Delete,
}

impl AuditOperation {
    /// Storage and API form.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditOperation::Create => "create",
            AuditOperation::Update => "update",
            AuditOperation::Delete => "delete",
        }
    }
}

impl std::fmt::Display for AuditOperation {
    /// Write the operation in its storage form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AuditOperation {
    type Err = ParseAuditLogError;

    /// Parse an operation from its storage form, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "create" => Ok(AuditOperation::Create),
            "update" => Ok(AuditOperation::Update),
            "delete" => Ok(AuditOperation::Delete),
            _ => Err(ParseAuditLogError::Operation {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for AuditOperation {
    type Error = ParseAuditLogError;

    /// Validate and convert the stored value into an operation.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// One management change: what was changed, how, by whom, and when. The
/// attribution columns are the ones a zone version carries.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AuditLog {
    pub id: AuditLogId,
    #[sqlx(try_from = "String")]
    pub entity: AuditEntity,
    /// The entity's name as its row spelled it; a grant's is its role's.
    pub entity_name: String,
    #[sqlx(try_from = "String")]
    pub operation: AuditOperation,
    /// The request path that made the change.
    #[sqlx(try_from = "String")]
    pub change_source: ChangeSource,
    /// A snapshot of the token or TSIG key identity, independent of the request path.
    #[sqlx(flatten, try_from = "ChangeActorColumns")]
    pub changed_by: Option<ChangeActor>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that `AuditEntity` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn audit_entity_spells_itself_once() {
        for value in AuditEntity::ALL {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<AuditEntity>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<AuditEntity>().unwrap(), value);
        }
        assert!("record".parse::<AuditEntity>().is_err());
    }

    /// Verify that `AuditOperation` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn audit_operation_spells_itself_once() {
        for value in [
            AuditOperation::Create,
            AuditOperation::Update,
            AuditOperation::Delete,
        ] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<AuditOperation>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<AuditOperation>().unwrap(), value);
        }
        assert!("revoke".parse::<AuditOperation>().is_err());
    }
}
