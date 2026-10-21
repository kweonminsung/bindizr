//! Record management changes in their transaction; reads require `audit:read`.

use std::fmt;

use bindizr_core::model::{
    audit_log::{AuditEntity, AuditLog, AuditLogId, AuditOperation},
    role_grant::Action,
};
use bindizr_db::{AuditLogSortField, SortOrder};
use chrono::Utc;

use crate::{
    Context, Transaction,
    authorization::Caller,
    error::ServiceError,
    pagination::{build_paginated_response, parse_setting, validate_page_limit},
    types::{AuditLogFilter, AuditLogResponse, PaginatedResponse},
    zone::version::ChangeAttribution,
};

/// Audit a management write before commit; `detail` describes changes without secrets.
pub(crate) async fn save_tx(
    tx: &mut Transaction<'_>,
    entity: AuditEntity,
    entity_name: &str,
    operation: AuditOperation,
    detail: Option<String>,
    attribution: &ChangeAttribution,
) -> Result<(), ServiceError> {
    Ok(bindizr_db::audit_log::create_tx(
        tx,
        AuditLog {
            id: AuditLogId::UNWRITTEN,
            entity,
            entity_name: entity_name.to_string(),
            operation,
            detail,
            change_source: attribution.source,
            changed_by: attribution.actor.clone(),
            created_at: Utc::now(),
        },
    )
    .await?)
}

/// `field old -> new` when an update moved a value, for its detail.
pub(crate) fn changed<T: PartialEq + fmt::Display>(field: &str, old: T, new: T) -> Option<String> {
    (old != new).then(|| format!("{field} {old} -> {new}"))
}

/// An update's detail: the fields it moved, or none when nothing moved.
pub(crate) fn join_changes(changes: impl IntoIterator<Item = Option<String>>) -> Option<String> {
    let changes: Vec<String> = changes.into_iter().flatten().collect();
    (!changes.is_empty()).then(|| changes.join(", "))
}

/// The rows `filter` selects, newest first unless it sorts otherwise. Count
/// and page are plain statements; drift between the two is accepted.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    filter: AuditLogFilter,
) -> Result<PaginatedResponse<AuditLogResponse>, ServiceError> {
    caller.authorize_action(Action::AuditRead)?;

    let filter = normalize_filter(filter)?;
    let total = bindizr_db::audit_log::count_by_filter(cx.db(), &filter).await?;
    let rows = bindizr_db::audit_log::list_by_filter(cx.db(), &filter).await?;
    Ok(build_paginated_response(
        rows.iter().map(AuditLogResponse::from).collect(),
        filter.limit,
        filter.offset,
        total,
    ))
}

/// Parse the listing's entity and sort, trim its name to the row spelling
/// every entity stores (lowercase), and bound its page.
fn normalize_filter(
    filter: AuditLogFilter,
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
        .map(str::to_ascii_lowercase);
    if let (Some(since), Some(until)) = (filter.since, filter.until)
        && since >= until
    {
        return Err(ServiceError::invalid_input("since must be before until"));
    }
    // Newest first is the log's natural order, whatever the field.
    let order = match filter.order.as_deref() {
        None => SortOrder::Desc,
        Some(order) => order.parse().map_err(ServiceError::invalid_input)?,
    };
    validate_page_limit(filter.limit)?;
    Ok(bindizr_db::audit_log::AuditLogFilter {
        entity,
        entity_name,
        since: filter.since,
        until: filter.until,
        sort: parse_setting::<AuditLogSortField>(filter.sort.as_deref())?,
        order,
        limit: filter.limit,
        offset: filter.offset,
    })
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::error::ErrorCode;

    /// Verify that `normalize_filter` parses the entity, lowercases the name, and bounds the page.
    #[test]
    fn normalize_filter_parses_entity_and_folds_name_case() {
        let filter = normalize_filter(AuditLogFilter {
            entity: Some(" TSIG_KEY ".to_string()),
            entity_name: Some(" Update-Key ".to_string()),
            limit: Some(10),
            offset: Some(5),
            ..AuditLogFilter::default()
        })
        .unwrap();

        assert_eq!(filter.entity, Some(AuditEntity::TsigKey));
        assert_eq!(filter.entity_name.as_deref(), Some("update-key"));
        assert_eq!(filter.limit, Some(10));
        assert_eq!(filter.offset, Some(5));
        assert_eq!(filter.sort, AuditLogSortField::CreatedAt);
        assert_eq!(filter.order, SortOrder::Desc);
    }

    /// Verify that `normalize_filter` reads the sort field and direction, and refuses unknown ones.
    #[test]
    fn normalize_filter_reads_sort_and_order() {
        let filter = normalize_filter(AuditLogFilter {
            sort: Some("entity_name".to_string()),
            order: Some("asc".to_string()),
            ..AuditLogFilter::default()
        })
        .unwrap();
        assert_eq!(filter.sort, AuditLogSortField::EntityName);
        assert_eq!(filter.order, SortOrder::Asc);

        for (sort, order) in [(Some("name"), None), (None, Some("newest"))] {
            let err = normalize_filter(AuditLogFilter {
                sort: sort.map(str::to_string),
                order: order.map(str::to_string),
                ..AuditLogFilter::default()
            })
            .unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput);
        }
    }

    /// Blank selectors normalize to absent without supplying a page limit.
    #[test]
    fn normalize_filter_reads_blank_selectors_as_absent() {
        let filter = normalize_filter(AuditLogFilter {
            entity: Some("".to_string()),
            entity_name: Some("   ".to_string()),
            ..AuditLogFilter::default()
        })
        .unwrap();

        assert_eq!(filter.entity, None);
        assert_eq!(filter.entity_name, None);
        assert_eq!(filter.limit, None);
    }

    /// Verify that `normalize_filter` rejects an unknown entity and an empty time window.
    #[test]
    fn normalize_filter_rejects_unknown_entity_and_inverted_window() {
        let unknown = normalize_filter(AuditLogFilter {
            entity: Some("record".to_string()),
            ..AuditLogFilter::default()
        })
        .unwrap_err();
        assert_eq!(unknown.code(), ErrorCode::InvalidInput);
        assert!(unknown.to_string().contains("tsig_key"), "{unknown}");

        let later = Utc.with_ymd_and_hms(2026, 10, 2, 0, 0, 0).unwrap();
        let inverted = normalize_filter(AuditLogFilter {
            since: Some(later),
            until: Some(later),
            ..AuditLogFilter::default()
        })
        .unwrap_err();
        assert_eq!(inverted.code(), ErrorCode::InvalidInput);
    }
}
