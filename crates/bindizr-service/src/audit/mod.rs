//! Save management changes in their transaction; reads require `log:read`.

use std::fmt;

use bindizr_core::model::audit_log::{AuditEntity, AuditLog, AuditLogId, AuditOperation};
use bindizr_core::model::role_grant::Action;
use chrono::Utc;

use crate::authorization::Caller;
use crate::change::ChangeOrigin;
use crate::error::ServiceError;
use crate::types::{AuditLogFilter, AuditLogResponse, PaginatedResponse};
use crate::{
    Context, Transaction, dnssec_policy, pagination, role, secondary, token, tsig_key, zone,
};

/// Audit a management write before commit; `detail` describes changes without secrets.
pub(crate) async fn save_tx(
    tx: &mut Transaction<'_>,
    entity: AuditEntity,
    entity_name: &str,
    operation: AuditOperation,
    detail: Option<String>,
    origin: &ChangeOrigin,
) -> Result<(), ServiceError> {
    Ok(bindizr_db::audit_log::create_tx(
        tx,
        AuditLog {
            id: AuditLogId::UNWRITTEN,
            entity,
            entity_name: entity_name.to_string(),
            operation,
            detail,
            change_source: origin.source,
            changed_by: origin.actor.clone(),
            created_at: Utc::now(),
        },
    )
    .await?)
}

/// Return `field old -> new` when an update moved a value, for its detail.
pub(crate) fn changed<T: PartialEq + fmt::Display>(field: &str, old: T, new: T) -> Option<String> {
    (old != new).then(|| format!("{field} {old} -> {new}"))
}

/// Join an update's detail: the fields it moved, or none when nothing moved.
pub(crate) fn join_changes(changes: impl IntoIterator<Item = Option<String>>) -> Option<String> {
    let changes: Vec<String> = changes.into_iter().flatten().collect();
    (!changes.is_empty()).then(|| changes.join(", "))
}

/// List the audit log entries `filter` selects, newest first unless it sorts otherwise. Count
/// and page are plain statements; drift between the two is accepted.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    filter: &AuditLogFilter,
) -> Result<PaginatedResponse<AuditLogResponse>, ServiceError> {
    caller.authorize_action(Action::LogRead)?;

    let filter = normalize_filter(filter)?;

    let total = bindizr_db::audit_log::count_by_filter(cx.db(), &filter).await?;
    let logs = bindizr_db::audit_log::list_by_filter(cx.db(), &filter).await?;

    Ok(pagination::build_paginated_response(
        logs.iter().map(AuditLogResponse::from).collect(),
        filter.limit,
        filter.offset,
        total,
    ))
}

/// Parse the listing's entity and sort, spell its name as that entity stores
/// it, and bound its page.
fn normalize_filter(
    filter: &AuditLogFilter,
) -> Result<bindizr_db::audit_log::AuditLogFilter, ServiceError> {
    let entity = filter
        .entity
        .as_deref()
        .map(str::trim)
        .filter(|entity| !entity.is_empty())
        .map(str::parse::<AuditEntity>)
        .transpose()
        .map_err(ServiceError::invalid_input)?;
    let entity_name = filter
        .entity_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| match entity {
            Some(AuditEntity::Zone) => {
                zone::normalize_name(name).map(|zone_name| zone_name.to_string())
            }
            Some(AuditEntity::TsigKey) => tsig_key::normalize_name(name),
            Some(AuditEntity::Token) => token::normalize_name(name),
            // A grant's row carries its role's name.
            Some(AuditEntity::Role | AuditEntity::RoleGrant) => role::normalize_name(name),
            Some(AuditEntity::Secondary) => secondary::normalize_name(name),
            Some(AuditEntity::DnssecPolicy) => dnssec_policy::normalize_name(name),
            // With no kind there is no one spelling to reach; fold what every kind folds.
            None => Ok(name.to_ascii_lowercase()),
        })
        .transpose()?;

    pagination::validate_time_window(filter.since, filter.until)?;

    // Newest first is the log's natural order, whatever the field.
    let defaults = bindizr_db::audit_log::AuditLogFilter::default();
    let sort = pagination::parse_setting(filter.sort.as_deref(), defaults.sort)?;
    let order = pagination::parse_setting(filter.order.as_deref(), defaults.order)?;
    pagination::validate_page_limit(filter.limit)?;

    Ok(bindizr_db::audit_log::AuditLogFilter {
        entity,
        entity_name,
        since: filter.since,
        until: filter.until,
        sort,
        order,
        limit: filter.limit,
        offset: filter.offset,
    })
}

#[cfg(test)]
mod tests;
