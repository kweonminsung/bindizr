//! Operations and results recorded by the activity log.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;
use utoipa::ToSchema;
use utoipa::openapi::schema::Type;
use utoipa::openapi::{ObjectBuilder, RefOr, Schema};

use crate::model::change::{ChangeActor, ChangeActorColumns, ChangeSource};

/// An operation name outside the activity catalog.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown activity operation '{value}'")]
pub struct ParseActivityOperationError {
    pub value: String,
}

macro_rules! activity_operations {
    ($($operation:ident => $name:literal),+ $(,)?) => {
        /// A named management operation, independent of transport and result.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum ActivityOperation {
            $(
                #[serde(rename = $name)]
                $operation,
            )+
        }

        impl ActivityOperation {
            /// Every operation in catalog order.
            pub const ALL: &'static [Self] = &[$(Self::$operation),+];

            /// Return the canonical operation name used in storage and on the wire.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$operation => $name,)+
                }
            }

            /// Return the kind of resource this operation addresses.
            pub fn entity(self) -> &'static str {
                self.as_str().split('.').next().unwrap_or_default()
            }

        }

        impl FromStr for ActivityOperation {
            type Err = ParseActivityOperationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($name => Ok(Self::$operation),)+
                    _ => Err(ParseActivityOperationError {
                        value: value.to_string(),
                    }),
                }
            }
        }
    };
}

activity_operations! {
    ZoneCreate => "zone.create",
    ZoneUpdate => "zone.update",
    ZoneDelete => "zone.delete",
    ZoneImport => "zone.import",
    ZoneNotify => "zone.notify",
    ZoneRollback => "zone.rollback",
    RecordCreate => "record.create",
    RecordUpdate => "record.update",
    RecordDelete => "record.delete",
    RecordBulkCreate => "record.bulk_create",
    NsupdateApply => "nsupdate.apply",
    ExternalDnsApply => "external_dns.apply",
    RoleCreate => "role.create",
    RoleDelete => "role.delete",
    RoleGrantCreate => "role_grant.create",
    RoleGrantDelete => "role_grant.delete",
    TokenCreate => "token.create",
    TokenDelete => "token.delete",
    TsigKeyCreate => "tsig_key.create",
    TsigKeyDelete => "tsig_key.delete",
    SecondaryCreate => "secondary.create",
    SecondaryUpdate => "secondary.update",
    SecondaryDelete => "secondary.delete",
    SecondaryCheck => "secondary.check",
    SecondaryCheckEnabled => "secondary.check_enabled",
    DnssecUpdate => "dnssec.update",
    DnssecEnable => "dnssec.enable",
    DnssecDisable => "dnssec.disable",
    DnssecSign => "dnssec.sign",
    DnssecCheckDs => "dnssec.check_ds",
    DnssecStartRollover => "dnssec.start_rollover",
    DnssecAdvanceRollover => "dnssec.advance_rollover",
    DnssecWithdraw => "dnssec.withdraw",
    DnssecCancelWithdrawal => "dnssec.cancel_withdrawal",
    DnssecImportKeys => "dnssec.import_keys",
    DnssecMaintain => "dnssec.maintain",
    DnssecPolicyCreate => "dnssec_policy.create",
    DnssecPolicyUpdate => "dnssec_policy.update",
    DnssecPolicyDelete => "dnssec_policy.delete",
}

impl fmt::Display for ActivityOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl utoipa::PartialSchema for ActivityOperation {
    /// Describe the same canonical operation names the activity listing returns.
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .enum_values(Some(Self::ALL.iter().copied().map(Self::as_str)))
            .description(Some(
                "A named management operation, independent of transport and result.",
            ))
            .into()
    }
}

impl utoipa::ToSchema for ActivityOperation {}

impl TryFrom<String> for ActivityOperation {
    type Error = ParseActivityOperationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// A result name outside the set the activity log accepts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown activity result '{value}'")]
pub struct ParseActivityResultError {
    pub value: String,
}

/// The result of the recorded operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActivityResult {
    /// A change to managed state committed.
    Changed,
    /// The operation completed without a committed change.
    Succeeded,
    /// The operation could not complete.
    Failed,
}

impl ActivityResult {
    /// Every supported result.
    pub const ALL: [Self; 3] = [Self::Changed, Self::Succeeded, Self::Failed];

    /// Return the canonical result name used in storage and on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for ActivityResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ActivityResult {
    type Err = ParseActivityResultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "changed" => Ok(Self::Changed),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => Err(ParseActivityResultError {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for ActivityResult {
    type Error = ParseActivityResultError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// Selected identity fields for the operation's target.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema, FromRow)]
pub struct ActivityTarget {
    /// The named administrative entity, such as a role or secondary.
    #[sqlx(rename = "target_name")]
    pub name: Option<String>,
    /// The stored zone name associated with the operation.
    pub zone_name: Option<String>,
    /// The identifier of a single stored record, when available.
    pub record_id: Option<i32>,
    /// The record's owner name, using the zone-relative name used in grants.
    pub record_name: Option<String>,
    /// The record's canonical type mnemonic.
    pub record_type: Option<String>,
}

/// A recorded operation result and its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, FromRow)]
pub struct ActivityLog {
    /// The database-assigned activity row ID.
    pub id: i64,
    #[sqlx(try_from = "String")]
    pub operation: ActivityOperation,
    #[sqlx(try_from = "String")]
    pub result: ActivityResult,
    #[sqlx(flatten)]
    pub target: ActivityTarget,
    #[sqlx(try_from = "String")]
    pub source: ChangeSource,
    /// The verified credential identity, when one was used.
    #[sqlx(flatten, try_from = "ChangeActorColumns")]
    pub actor: Option<ChangeActor>,
    /// The time this activity was recorded.
    pub created_at: DateTime<Utc>,
    /// Selected change detail that excludes credentials and record values.
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn activity_operation_spells_itself_once() {
        for &operation in ActivityOperation::ALL {
            let text = operation.as_str();
            assert_eq!(serde_json::to_value(operation).unwrap(), json!(text));
            assert_eq!(
                serde_json::from_value::<ActivityOperation>(json!(text)).unwrap(),
                operation
            );
            assert_eq!(text.parse::<ActivityOperation>().unwrap(), operation);
        }
    }

    #[test]
    fn activity_result_spells_itself_once() {
        for result in ActivityResult::ALL {
            let text = result.as_str();
            assert_eq!(serde_json::to_value(result).unwrap(), json!(text));
            assert_eq!(
                serde_json::from_value::<ActivityResult>(json!(text)).unwrap(),
                result
            );
            assert_eq!(text.parse::<ActivityResult>().unwrap(), result);
        }
    }
}
