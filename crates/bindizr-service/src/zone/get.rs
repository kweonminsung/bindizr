use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::zone::Zone;
use bindizr_db::{LockLevel, SortOrder, ZoneSortField};

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::{PaginatedResponse, ZoneFilter, ZoneResponse};
use crate::{Context, Transaction, pagination, ttl, zone};

/// Find the DNS plane's view of a zone: a disabled one is absent rather than
/// served. The nsupdate apply and the transfer authorization read it.
pub(crate) async fn find_served_by_name_tx(
    tx: &mut Transaction<'_>,
    zone_name: &ZoneName,
    lock_level: LockLevel,
) -> Result<Option<Zone>, ServiceError> {
    Ok(bindizr_db::zone::get_by_name_tx(tx, zone_name, lock_level)
        .await?
        .filter(|zone| zone.enabled))
}

/// Find the DNS plane's view of a zone outside a transaction: a disabled one
/// is absent rather than served.
pub(crate) async fn find_served_by_name(
    cx: &Context,
    zone_name: &ZoneName,
) -> Result<Option<Zone>, ServiceError> {
    Ok(bindizr_db::zone::get_by_name(cx.db(), zone_name)
        .await?
        .filter(|zone| zone.enabled))
}

/// Probe the database with a cheap round-trip (limit-1 zones probe), for
/// health checks.
pub async fn probe_table(cx: &Context) -> Result<(), ServiceError> {
    Ok(bindizr_db::zone::probe_table(cx.db()).await?)
}

/// List the zones the DNS plane serves, as the NOTIFY fan-out reads them.
pub async fn list(cx: &Context) -> Result<Vec<Zone>, ServiceError> {
    let zones = bindizr_db::zone::list_all(cx.db())
        .await
        .map_err(|error| ServiceError::internal_with_source("failed to fetch zones", error))?;
    Ok(zones.into_iter().filter(|zone| zone.enabled).collect())
}

/// Count all zones, for reports that expose no zone data: metrics, daemon
/// status, doctor.
pub async fn count_all(cx: &Context) -> Result<u64, ServiceError> {
    Ok(
        bindizr_db::zone::count_by_filter(cx.db(), &bindizr_db::zone::ZoneFilter::default())
            .await?,
    )
}

/// List the zones matching `filter` that the caller may see, restricted in
/// SQL so pagination stays database-side.
pub async fn list_by_filter(
    cx: &Context,
    caller: &Caller,
    filter: &ZoneFilter,
) -> Result<PaginatedResponse<ZoneResponse>, ServiceError> {
    let default_ttl = filter
        .default_ttl
        .map(ttl::validate_record_ttl)
        .transpose()?;
    let min_default_ttl = filter
        .min_default_ttl
        .map(ttl::validate_record_ttl)
        .transpose()?;
    let max_default_ttl = filter
        .max_default_ttl
        .map(ttl::validate_record_ttl)
        .transpose()?;

    let scope_role_id = caller.scope_role_id();
    pagination::validate_page_limit(filter.limit)?;
    let limit = filter.limit;
    let offset = filter.offset;

    let zone_filter = bindizr_db::zone::ZoneFilter {
        name: filter
            .name
            .as_deref()
            .map(zone::normalize_name)
            .transpose()?,
        id: filter.id,
        // The stored spelling is the normalizers', so the filter binds it.
        mname: filter
            .mname
            .as_deref()
            .map(zone::normalize_mname)
            .transpose()?,
        rname: filter
            .rname
            .as_deref()
            .map(zone::normalize_rname)
            .transpose()?,
        default_ttl,
        min_default_ttl,
        max_default_ttl,
        serial: filter.serial,
        min_serial: filter.min_serial,
        max_serial: filter.max_serial,
        created_after: filter.created_after,
        created_before: filter.created_before,
        signed: filter.signed,
        enabled: filter.enabled,
        search: filter.search.clone(),
        scope_role_id,
        sort: pagination::parse_setting(filter.sort.as_deref(), ZoneSortField::default())?,
        order: pagination::parse_setting(filter.order.as_deref(), SortOrder::default())?,
        limit,
        offset,
    };

    let total = bindizr_db::zone::count_by_filter(cx.db(), &zone_filter).await?;
    let zones = bindizr_db::zone::list_by_filter(cx.db(), &zone_filter).await?;
    let items = zones.iter().map(ZoneResponse::from).collect();

    Ok(pagination::build_paginated_response(
        items, limit, offset, total,
    ))
}

/// Get a zone by name for `caller`; a zone it cannot see reads as
/// `NotFound`, so grants cannot be probed.
pub async fn get_by_name(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<ZoneResponse, ServiceError> {
    let zone = lookup_by_name(cx, zone_name).await?;
    caller.authorize_zone_visible(&zone)?;
    Ok(ZoneResponse::from(&zone))
}

/// Look up a zone unchecked, `NotFound` on a miss, for service-internal use;
/// anything a front end reaches goes through [`get_by_name`].
pub(crate) async fn lookup_by_name(
    cx: &Context,
    zone_name: &ZoneName,
) -> Result<Zone, ServiceError> {
    bindizr_db::zone::get_by_name(cx.db(), zone_name)
        .await?
        .ok_or_else(|| ServiceError::zone_not_found(zone_name))
}

/// Look up a zone in `tx` at `lock_level`, returning `NotFound` if absent.
/// The owning flow must authorize the locked row before exposing or changing it.
pub(crate) async fn lookup_by_name_tx(
    tx: &mut Transaction<'_>,
    zone_name: &ZoneName,
    lock_level: LockLevel,
) -> Result<Zone, ServiceError> {
    bindizr_db::zone::get_by_name_tx(tx, zone_name, lock_level)
        .await?
        .ok_or_else(|| ServiceError::zone_not_found(zone_name))
}
