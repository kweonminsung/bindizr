//! Publish managed operations in the transaction that makes them visible.

use std::fmt;

use bindizr_core::dns::name::OwnerName;
use bindizr_core::model::activity_log::{
    ActivityLog, ActivityOperation, ActivityResult, ActivityTarget,
};
use bindizr_core::model::role_grant::Action;
use bindizr_db::{SortOrder, activity_log};
use chrono::Utc;

use crate::authorization::Caller;
use crate::change::ChangeOrigin;
use crate::error::ServiceError;
use crate::types::{ActivityLogFilter, PaginatedResponse};
use crate::{
    Context, Transaction, dnssec_policy, pagination, record, role, secondary, text, token,
    tsig_key, zone,
};

/// Write a committed change event after the domain writes and locks in this transaction.
pub(crate) async fn save_tx(
    tx: &mut Transaction<'_>,
    operation: ActivityOperation,
    target: ActivityTarget,
    origin: &ChangeOrigin,
) -> Result<(), ServiceError> {
    save_detail_tx(tx, operation, ActivityResult::Changed, target, None, origin).await
}

/// Add one non-secret activity record to the operation's transaction.
pub(crate) async fn save_detail_tx(
    tx: &mut Transaction<'_>,
    operation: ActivityOperation,
    result: ActivityResult,
    target: ActivityTarget,
    detail: Option<String>,
    origin: &ChangeOrigin,
) -> Result<(), ServiceError> {
    activity_log::create_tx(
        tx,
        &ActivityLog {
            id: 0,
            operation,
            result,
            target,
            detail,
            source: origin.source,
            actor: origin.actor.clone(),
            created_at: Utc::now(),
        },
    )
    .await?;
    Ok(())
}

/// Return a change to a non-secret field in its stored spelling.
pub(crate) fn changed<T: PartialEq + fmt::Display>(field: &str, old: T, new: T) -> Option<String> {
    (old != new).then(|| format!("{field} {old} -> {new}"))
}

/// Join the fields that an update moved.
pub(crate) fn join_changes(changes: impl IntoIterator<Item = Option<String>>) -> Option<String> {
    let changes: Vec<String> = changes.into_iter().flatten().collect();
    (!changes.is_empty()).then(|| changes.join(", "))
}

/// Identify one named administrative target.
pub(crate) fn named_target(name: &str) -> ActivityTarget {
    ActivityTarget {
        name: Some(name.to_string()),
        ..Default::default()
    }
}

/// Return whether an administrative update changed its reported fields.
pub(crate) fn update_result(detail: Option<&str>) -> ActivityResult {
    if detail.is_some() {
        ActivityResult::Changed
    } else {
        ActivityResult::Succeeded
    }
}

/// Write one event for each target changed by the same operation.
pub(crate) async fn save_many_tx(
    tx: &mut Transaction<'_>,
    operation: ActivityOperation,
    targets: Vec<ActivityTarget>,
    origin: &ChangeOrigin,
) -> Result<(), ServiceError> {
    save_operations_tx(
        tx,
        targets.into_iter().map(|target| (operation, target)),
        origin,
    )
    .await
}

/// Write related changes in their operation order.
pub(crate) async fn save_operations_tx(
    tx: &mut Transaction<'_>,
    operations: impl IntoIterator<Item = (ActivityOperation, ActivityTarget)>,
    origin: &ChangeOrigin,
) -> Result<(), ServiceError> {
    let created_at = Utc::now();
    let logs: Vec<ActivityLog> = operations
        .into_iter()
        .map(|(operation, target)| ActivityLog {
            id: 0,
            operation,
            result: ActivityResult::Changed,
            target,
            detail: None,
            source: origin.source,
            actor: origin.actor.clone(),
            created_at,
        })
        .collect();
    activity_log::create_many_tx(tx, &logs).await?;
    Ok(())
}

/// Save a completed operation that has no domain transaction.
pub(crate) async fn save_result(
    cx: &Context,
    operation: ActivityOperation,
    result: ActivityResult,
    target: ActivityTarget,
    origin: &ChangeOrigin,
) {
    let saved = async {
        let mut tx = cx.db().begin().await?;
        save_detail_tx(&mut tx, operation, result, target, None, origin).await?;
        tx.commit().await.map_err(ServiceError::from)
    }
    .await;
    if let Err(error) = saved {
        log::warn!("Failed to save activity for {operation}: {error}");
    }
}

/// List the activity log rows selected by an interactive filter.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    filter: &ActivityLogFilter,
) -> Result<PaginatedResponse<ActivityLog>, ServiceError> {
    caller.authorize_action(Action::LogRead)?;

    let filter = normalize_filter(filter)?;
    let total = activity_log::count_by_filter(cx.db(), &filter).await?;
    let items = activity_log::list_by_filter(cx.db(), &filter).await?;
    Ok(pagination::build_paginated_response(
        items,
        filter.limit,
        filter.offset,
        total,
    ))
}

fn normalize_filter(
    filter: &ActivityLogFilter,
) -> Result<activity_log::ActivityLogFilter, ServiceError> {
    let entity = query_text(filter.entity.as_deref()).map(str::to_ascii_lowercase);
    if let Some(entity) = &entity
        && !ActivityOperation::ALL
            .iter()
            .any(|operation| operation.entity() == entity.as_str())
    {
        return Err(ServiceError::invalid_input(format!(
            "unknown activity entity '{entity}'"
        )));
    }
    let operation = text::parse_optional::<ActivityOperation>(filter.operation.as_deref())?;
    let name = query_text(filter.name.as_deref())
        .map(|name| {
            match entity
                .as_deref()
                .or_else(|| operation.map(ActivityOperation::entity))
            {
                Some("zone" | "record" | "dnssec") => {
                    zone::normalize_name(name).map(|zone| zone.to_string())
                }
                Some("tsig_key") => tsig_key::normalize_name(name),
                Some("token") => token::normalize_name(name),
                Some("role" | "role_grant") => role::normalize_name(name),
                Some("secondary") => secondary::normalize_name(name),
                Some("dnssec_policy") => dnssec_policy::normalize_name(name),
                _ => Ok(name.to_ascii_lowercase()),
            }
        })
        .transpose()?;
    let zone_name = query_text(filter.zone_name.as_deref())
        .map(zone::normalize_name)
        .transpose()?;
    let record_name = query_text(filter.record_name.as_deref())
        .map(|owner| match &zone_name {
            Some(zone_name) => record::normalize_record_owner_name(owner, zone_name),
            None if owner == OwnerName::APEX => Ok(OwnerName::apex()),
            None => OwnerName::from_row(owner).map_err(ServiceError::invalid_input),
        })
        .transpose()?
        .map(|name| name.to_string());
    let record_type = query_text(filter.record_type.as_deref())
        .map(record::parse_record_type)
        .transpose()?
        .map(|record_type| record_type.to_string());

    pagination::validate_time_window(filter.since, filter.until)?;
    pagination::validate_page_limit(filter.limit)?;
    let defaults = activity_log::ActivityLogFilter::default();
    Ok(activity_log::ActivityLogFilter {
        entity,
        operation,
        result: text::parse_optional::<ActivityResult>(filter.result.as_deref())?,
        name,
        zone_name: zone_name.map(|zone_name| zone_name.to_string()),
        record_name,
        record_type,
        since: filter.since,
        until: filter.until,
        sort: pagination::parse_setting(filter.sort.as_deref(), defaults.sort)?,
        order: pagination::parse_setting(filter.order.as_deref(), SortOrder::Desc)?,
        limit: filter.limit,
        offset: filter.offset,
    })
}

fn query_text(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests;
