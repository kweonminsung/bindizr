//! Audit log payloads.

use bindizr_core::model::audit_log::{AuditEntity, AuditLog, AuditLogId, AuditOperation};
use bindizr_core::model::change::{ChangeActor, ChangeSource};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Query parameters of the audit log listing: which changes, and the page.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct AuditLogFilter {
    /// Only changes to this kind of entity: `token`, `role`, `role_grant`,
    /// `tsig_key`, `secondary`, `dnssec_policy`, or `zone`.
    #[schema(example = "token")]
    pub entity: Option<String>,
    /// Only changes to the entity of this name; a grant's is its role's.
    #[schema(example = "external-dns")]
    pub entity_name: Option<String>,
    /// Only changes made at or after this time (RFC 3339).
    #[schema(example = "2026-10-01T00:00:00Z")]
    pub since: Option<DateTime<Utc>>,
    /// Only changes made before this time (RFC 3339).
    #[schema(example = "2026-11-01T00:00:00Z")]
    pub until: Option<DateTime<Utc>>,
    /// `created_at` (the default), `entity`, `entity_name`, or `operation`.
    #[schema(example = "created_at")]
    pub sort: Option<String>,
    /// `desc` (the default) or `asc`.
    #[schema(example = "desc")]
    pub order: Option<String>,
    /// Items per page; the HTTP API defaults it, the daemon socket does not.
    #[schema(example = 50)]
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// One row of the audit log: what was changed, how, by whom, and when.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct AuditLogResponse {
    #[schema(example = 1, value_type = i32)]
    pub id: AuditLogId,
    pub entity: AuditEntity,
    /// The entity's name as its row spelled it; a grant's is its role's.
    #[schema(example = "external-dns")]
    pub entity_name: String,
    pub operation: AuditOperation,
    /// What the change set or moved (`enabled true -> false`), or what a
    /// deletion took with it, in the request's field names; null when there
    /// is nothing to say, never a secret.
    #[schema(example = "role_name external-dns-prod, expires_at never")]
    pub detail: Option<String>,
    /// The request path (`api` or `socket`) that made the change.
    pub change_source: ChangeSource,
    /// Token kind and name. Null for socket commands and unauthenticated
    /// API requests.
    pub changed_by: Option<ChangeActor>,
    pub created_at: DateTime<Utc>,
}

impl From<&AuditLog> for AuditLogResponse {
    /// Render a stored row.
    fn from(log: &AuditLog) -> Self {
        AuditLogResponse {
            id: log.id,
            entity: log.entity,
            entity_name: log.entity_name.clone(),
            operation: log.operation,
            detail: log.detail.clone(),
            change_source: log.change_source,
            changed_by: log.changed_by.clone(),
            created_at: log.created_at,
        }
    }
}
