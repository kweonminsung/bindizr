use bindizr_core::dns::name::ZoneName;
use bindizr_db::LockLevel;

use crate::{
    Context, Transaction,
    authorization::Caller,
    error::ServiceError,
    model::zone::Zone,
    pagination::{build_paginated_response, normalize_page_limit, parse_setting},
    types::{PaginatedResponse, ZoneFilter, ZoneResponse},
};

/// The DNS plane's view of a zone: a disabled one is absent rather than
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

/// Read a zone in the caller's transaction at `lock_level`, including disabled zones
/// so imports can still write their records.
pub(crate) async fn find_by_name_tx(
    tx: &mut Transaction<'_>,
    zone_name: &ZoneName,
    lock_level: LockLevel,
) -> Result<Option<Zone>, ServiceError> {
    Ok(bindizr_db::zone::get_by_name_tx(tx, zone_name, lock_level).await?)
}

/// Cheap database round-trip (limit-1 zones probe), for health checks.
pub async fn ping(cx: &Context) -> Result<(), ServiceError> {
    Ok(bindizr_db::zone::ping(cx.db()).await?)
}

/// The zones the DNS plane serves: the catalog's membership and the NOTIFY
/// fan-out read it.
pub async fn list(cx: &Context) -> Result<Vec<Zone>, ServiceError> {
    let zones = bindizr_db::zone::list_all(cx.db()).await.map_err(|e| {
        log::error!("Failed to fetch zones: {}", e);
        ServiceError::internal_with_source("failed to fetch zones", e)
    })?;
    Ok(zones.into_iter().filter(|zone| zone.enabled).collect())
}

/// All zones, for the unauthenticated metrics endpoint.
pub async fn count_all(cx: &Context) -> Result<u64, ServiceError> {
    Ok(bindizr_db::zone::count_by_filter(cx.db(), bindizr_db::zone::ZoneFilter::default()).await?)
}

/// Count the zones visible to `caller`.
pub async fn count(cx: &Context, caller: &Caller) -> Result<u64, ServiceError> {
    Ok(bindizr_db::zone::count_by_filter(
        cx.db(),
        bindizr_db::zone::ZoneFilter {
            scope_role_id: caller.scope_role_id(),
            ..bindizr_db::zone::ZoneFilter::default()
        },
    )
    .await?)
}

/// List the zones matching `filter` that the caller may see, restricted in
/// SQL so pagination stays database-side.
pub async fn list_by_filter(
    cx: &Context,
    caller: &Caller,
    filter: ZoneFilter,
) -> Result<PaginatedResponse<ZoneResponse>, ServiceError> {
    let scope_role_id = caller.scope_role_id();
    let limit = Some(normalize_page_limit(filter.limit)?);
    let offset = filter.offset;
    let serial = filter.serial;
    let min_serial = filter.min_serial;
    let max_serial = filter.max_serial;

    let zone_filter = bindizr_db::zone::ZoneFilter {
        name: filter.name,
        id: filter.id,
        mname: filter.mname,
        rname: filter.rname,
        default_ttl: filter.default_ttl,
        min_default_ttl: filter.min_default_ttl,
        max_default_ttl: filter.max_default_ttl,
        serial,
        min_serial,
        max_serial,
        created_after: filter.created_after,
        created_before: filter.created_before,
        signed: filter.signed,
        enabled: filter.enabled,
        search: filter.search,
        scope_role_id,
        sort: parse_setting(filter.sort.as_deref())?,
        order: parse_setting(filter.order.as_deref())?,
        limit,
        offset,
    };

    let total = bindizr_db::zone::count_by_filter(cx.db(), zone_filter.clone()).await?;
    let zones = bindizr_db::zone::list_by_filter(cx.db(), zone_filter).await?;
    let items = zones.iter().map(ZoneResponse::from).collect();
    Ok(build_paginated_response(items, limit, offset, total))
}

/// Fetch a zone by name for `caller`; a zone it cannot see reads as
/// `NotFound`, so grants cannot be probed.
pub async fn get_by_name(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<Zone, ServiceError> {
    let zone = lookup_by_name(cx, zone_name).await?;
    caller.authorize_zone_visible(&zone)?;
    Ok(zone)
}

/// The unchecked lookup, `NotFound` on a miss, for service-internal use;
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
