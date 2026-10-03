use bindizr_core::{
    dns::name::{OwnerName, ZoneName, decode_name_labels, labels_to_presentation},
    model::record::RecordId,
};
use bindizr_db::{dnssec_record::DnssecRecordFilter, record::RecordFilter};

use super::ListedRecord;
use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    model::{dnssec_record::DnssecRecordType, record::RecordType},
    pagination::{build_paginated_response, normalize_page_limit, parse_setting},
    types::{GetRecordResponse, GetRecordsFilter, PaginatedResponse, ZoneView},
    zone::{self, validation::normalize_name},
};

/// Which plane a `type` filter names: a user record type, or a derived
/// DNSSEC type when the signed view is requested.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
enum TypeFilter {
    Any,
    User(RecordType),
    Derived(DnssecRecordType),
}

/// Resolve a `type` filter to its plane.
fn parse_type_filter(value: Option<&str>, view: ZoneView) -> Result<TypeFilter, ServiceError> {
    let Some(value) = value else {
        return Ok(TypeFilter::Any);
    };
    match value.parse::<RecordType>() {
        Ok(record_type) => Ok(TypeFilter::User(record_type)),
        Err(err) => {
            if view == ZoneView::Signed
                && let Ok(record_type) = value.to_uppercase().parse::<DnssecRecordType>()
            {
                return Ok(TypeFilter::Derived(record_type));
            }
            Err(ServiceError::invalid_input(err))
        }
    }
}

/// Every record, for the unauthenticated metrics endpoint.
pub async fn count_all(cx: &Context) -> Result<u64, ServiceError> {
    Ok(bindizr_db::record::count_by_filter(cx.db(), RecordFilter::default()).await?)
}

/// List records with zone names, applying caller grants and pagination in SQL.
/// Signed records follow user records, support name search, and reject value filters.
/// Priority filters omit signed records; unknown or invisible zones yield empty pages for scoped callers.
pub async fn list_with_zone_by_filter(
    cx: &Context,
    caller: &Caller,
    filter: GetRecordsFilter,
) -> Result<PaginatedResponse<GetRecordResponse>, ServiceError> {
    let scope_role_id = caller.scope_role_id();
    let zone_name = filter
        .zone_name
        .as_deref()
        .map(normalize_name)
        .transpose()?;
    let limit = Some(normalize_page_limit(filter.limit)?);
    let offset = filter.offset;
    let view = ZoneView::from_signed(filter.signed.unwrap_or(false));

    // Scoped callers read unknown and invisible zones alike as empty
    // pages, so skip the 404 probe.
    if let Some(name) = zone_name.as_ref()
        && scope_role_id.is_none()
    {
        zone::lookup_by_name(cx, name).await?;
    }

    let name = build_record_name_filter(filter.name, zone_name.as_ref());
    let type_filter = parse_type_filter(filter.record_type.as_deref(), view)?;

    // A derived row's rdata is wire bytes, so no `LIKE` reaches it; asking
    // for both would answer a narrower question than the one put.
    if view == ZoneView::Signed && filter.value.is_some() {
        return Err(ServiceError::invalid_input(
            "value cannot narrow the derived DNSSEC records; drop value, or drop signed",
        ));
    }

    let user_plane = !matches!(type_filter, TypeFilter::Derived(_));
    // A derived row carries no priority, so a priority filter answers
    // "none of them" — which is what leaving the plane out returns.
    let derived_plane = view == ZoneView::Signed
        && !matches!(type_filter, TypeFilter::User(_))
        && filter.priority.is_none()
        && filter.min_priority.is_none()
        && filter.max_priority.is_none();

    let record_filter = RecordFilter {
        zone_name: zone_name.clone(),
        name: name.clone(),
        record_type: match &type_filter {
            TypeFilter::User(record_type) => Some(*record_type),
            _ => None,
        },
        value: filter.value,
        ttl: filter.ttl,
        min_ttl: filter.min_ttl,
        max_ttl: filter.max_ttl,
        priority: filter.priority,
        min_priority: filter.min_priority,
        max_priority: filter.max_priority,
        search: filter.search.clone(),
        scope_role_id,
        sort: parse_setting(filter.sort.as_deref())?,
        order: parse_setting(filter.order.as_deref())?,
        limit,
        offset,
    };
    let derived_filter = DnssecRecordFilter {
        zone_name,
        name,
        record_type: match type_filter {
            TypeFilter::Derived(record_type) => Some(i32::from(record_type.wire_type())),
            _ => None,
        },
        ttl: filter.ttl,
        min_ttl: filter.min_ttl,
        max_ttl: filter.max_ttl,
        search: filter.search.clone(),
        scope_role_id,
        limit: None,
        offset: None,
    };

    let user_total = if user_plane {
        bindizr_db::record::count_by_filter(cx.db(), record_filter.clone()).await?
    } else {
        0
    };
    let derived_total = if derived_plane {
        bindizr_db::dnssec_record::count_by_filter(cx.db(), derived_filter.clone()).await?
    } else {
        0
    };

    let start = offset.unwrap_or(0);
    let mut items: Vec<ListedRecord> = Vec::new();
    if user_plane && start < user_total {
        items.extend(
            bindizr_db::record::list_by_filter_with_zone(cx.db(), record_filter)
                .await?
                .into_iter()
                .map(ListedRecord::User),
        );
    }
    // The derived plane pages after the user plane: it starts where the
    // window passed the user rows and fills what the limit still holds.
    let remaining = limit.map(|limit| limit.saturating_sub(items.len() as u32));
    if derived_plane && remaining != Some(0) {
        items.extend(
            bindizr_db::dnssec_record::list_by_filter_with_zone(
                cx.db(),
                DnssecRecordFilter {
                    limit: remaining,
                    offset: Some(start.saturating_sub(user_total)),
                    ..derived_filter
                },
            )
            .await?
            .into_iter()
            .map(ListedRecord::Derived),
        );
    }

    let items = items
        .iter()
        .map(|item| super::build_record_response(caller, item))
        .collect();
    Ok(build_paginated_response(
        items,
        limit,
        offset,
        user_total + derived_total,
    ))
}

/// Fetch a record by id with the caller's actions on it. A record the
/// caller cannot read reads as `NotFound`, so ids cannot be probed.
pub async fn get(
    cx: &Context,
    caller: &Caller,
    record_id: RecordId,
) -> Result<GetRecordResponse, ServiceError> {
    let record = match bindizr_db::record::get_with_zone(cx.db(), record_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return Err(ServiceError::record_not_found(record_id)),
        Err(e) => {
            log::error!("Failed to fetch record: {}", e);
            return Err(ServiceError::internal_with_source(
                "failed to fetch record",
                e,
            ));
        }
    };

    if !caller.sees_record(record.zone_id, &record.name, Some(&record.record_type)) {
        return Err(ServiceError::record_not_found(record_id));
    }
    Ok(super::build_record_response(
        caller,
        &ListedRecord::User(record),
    ))
}

/// Normalize a name filter for stored-owner and FQDN comparisons.
fn build_record_name_filter(name: Option<String>, zone_name: Option<&ZoneName>) -> Option<String> {
    name.and_then(|name| {
        let trimmed = name.trim();
        // An empty value is no filter. Left to fall through it would spell the
        // apex, which rows hold as the empty string, and match every apex row.
        if trimmed.is_empty() {
            return None;
        }
        let Some(zone) = zone_name else {
            // No zone to build an FQDN against, so the apex can only be matched
            // by the sentinel rows hold it as.
            if trimmed == OwnerName::APEX {
                return Some(OwnerName::apex().to_stored());
            }
            // Rendered as rows hold it: a relative name against the owner, an
            // absolute one against the FQDN the query builds.
            return Some(match decode_name_labels(trimmed) {
                Ok((labels, absolute)) => {
                    let rendered = labels_to_presentation(&labels);
                    if absolute {
                        format!("{rendered}.")
                    } else {
                        rendered
                    }
                }
                Err(_) => trimmed.to_string(),
            });
        };

        // The query compares the filter against both the stored owner and the
        // FQDN it builds from it, so spell it the way rows do. Anything that is
        // not a name passes through to match literally.
        if let Ok(owner) = OwnerName::parse_absolute_in_zone(trimmed, zone) {
            return Some(owner.to_fqdn(zone));
        }
        Some(match OwnerName::parse_in_zone(trimmed, zone) {
            Ok(owner) => owner.to_stored(),
            Err(_) => trimmed.to_string(),
        })
    })
}
