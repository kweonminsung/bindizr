use bindizr_core::dns::serial_to_i32;
use bindizr_db::{
    LockLevel, dnssec_record::DnssecRecordFilter, record::RecordFilter, zone::ZoneFilter,
};

use super::validation::normalize_zone_name;
use crate::{
    Context, Transaction,
    authorization::Caller,
    db,
    error::ServiceError,
    model::{zone::Zone, zone_change::ZoneChange},
    types::{
        GetZoneResponse, GetZonesFilter, PaginatedResponse, normalize_page_limit, parse_setting,
    },
};

/// The DNS plane's view of a zone: a disabled one is absent rather than
/// served. The nsupdate apply and the transfer authorization read it.
pub(crate) async fn find_served_by_name_tx(
    tx: &mut Transaction<'_>,
    zone_name: &str,
    lock_level: LockLevel,
) -> Result<Option<Zone>, ServiceError> {
    let lookup_name = normalize_zone_name(zone_name)?;
    Ok(
        db::zone::get_by_name_tx(tx, lookup_name.as_str(), lock_level)
            .await?
            .filter(|zone| zone.enabled),
    )
}

/// Fetch a zone by name within the caller's transaction at `lock_level`,
/// whether or not it is served. The import reads it this way because a
/// disabled zone still takes records.
pub(crate) async fn find_by_name_tx(
    tx: &mut Transaction<'_>,
    zone_name: &str,
    lock_level: LockLevel,
) -> Result<Option<Zone>, ServiceError> {
    let lookup_name = normalize_zone_name(zone_name)?;
    Ok(db::zone::get_by_name_tx(tx, lookup_name.as_str(), lock_level).await?)
}

/// Count journal rows in `(from_serial, to_serial]` for the IXFR size estimate.
pub async fn count_changes_between_serials(
    cx: &Context,
    zone_id: i32,
    from_serial: i32,
    to_serial: i32,
) -> Result<u64, ServiceError> {
    Ok(db::zone_change::count_between_serials(cx.db(), zone_id, from_serial, to_serial).await?)
}

/// Journal rows in `(from_serial, to_serial]`, ordered by serial then row id.
pub async fn list_changes_between_serials(
    cx: &Context,
    zone_id: i32,
    from_serial: i32,
    to_serial: i32,
) -> Result<Vec<ZoneChange>, ServiceError> {
    Ok(db::zone_change::list_between_serials(cx.db(), zone_id, from_serial, to_serial).await?)
}

/// Cheap database round-trip (limit-1 zones probe), for health checks.
pub async fn ping(cx: &Context) -> Result<(), ServiceError> {
    db::zone::ping(cx.db())
        .await
        .map_err(|e| ServiceError::internal(format!("failed to reach the zones table: {}", e)))
}

/// The zones the DNS plane serves: the catalog's membership and the NOTIFY
/// fan-out read it.
pub async fn list(cx: &Context) -> Result<Vec<Zone>, ServiceError> {
    let zones = db::zone::list_all(cx.db()).await.map_err(|e| {
        log::error!("Failed to fetch zones: {}", e);
        ServiceError::internal("Failed to fetch zones")
    })?;
    Ok(zones.into_iter().filter(|zone| zone.enabled).collect())
}

/// Every zone, for the unauthenticated metrics endpoint.
pub async fn count_all(cx: &Context) -> Result<u64, ServiceError> {
    Ok(db::zone::count_by_filter(cx.db(), ZoneFilter::default()).await?)
}

/// Count the zones visible to `caller`.
pub async fn count(cx: &Context, caller: &Caller) -> Result<u64, ServiceError> {
    Ok(db::zone::count_by_filter(
        cx.db(),
        ZoneFilter {
            scope_token_id: caller.scope_token_id(),
            ..ZoneFilter::default()
        },
    )
    .await?)
}

/// List the zones matching `filter` that the caller may see, restricted in
/// SQL so pagination stays database-side.
pub async fn list_by_filter(
    cx: &Context,
    caller: &Caller,
    filter: GetZonesFilter,
) -> Result<PaginatedResponse<GetZoneResponse>, ServiceError> {
    let scope_token_id = caller.scope_token_id();
    let limit = Some(normalize_page_limit(filter.limit)?);
    let offset = filter.offset;

    let zone_filter = ZoneFilter {
        name: filter.name,
        id: filter.id,
        mname: filter.mname,
        rname: filter.rname,
        default_ttl: filter.default_ttl,
        min_default_ttl: filter.min_default_ttl,
        max_default_ttl: filter.max_default_ttl,
        serial: filter
            .serial
            .map(serial_to_i32)
            .transpose()
            .map_err(ServiceError::invalid_input)?,
        min_serial: filter
            .min_serial
            .map(serial_to_i32)
            .transpose()
            .map_err(ServiceError::invalid_input)?,
        max_serial: filter
            .max_serial
            .map(serial_to_i32)
            .transpose()
            .map_err(ServiceError::invalid_input)?,
        created_after: filter.created_after,
        created_before: filter.created_before,
        signed: filter.signed,
        enabled: filter.enabled,
        search: filter.search,
        scope_token_id,
        sort: parse_setting(filter.sort.as_deref())?,
        order: parse_setting(filter.order.as_deref())?,
        limit,
        offset,
    };

    let total = db::zone::count_by_filter(cx.db(), zone_filter.clone()).await?;
    let zones = db::zone::list_by_filter(cx.db(), zone_filter).await?;
    let items = zones.iter().map(GetZoneResponse::from_zone).collect();
    Ok(PaginatedResponse::from_page(items, limit, offset, total))
}

/// Fetch a zone by name for `caller`; a zone it cannot see reads as
/// `NotFound`, so grants cannot be probed.
pub async fn get_by_name(
    cx: &Context,
    caller: &Caller,
    zone_name: &str,
) -> Result<Zone, ServiceError> {
    let zone = lookup_by_name(cx, zone_name).await?;
    caller.authorize_zone_visible(&zone)?;
    Ok(zone)
}

/// The unchecked lookup, `NotFound` on a miss, for service-internal use;
/// anything a front end reaches goes through [`get_by_name`].
pub(crate) async fn lookup_by_name(cx: &Context, zone_name: &str) -> Result<Zone, ServiceError> {
    // Canonical, like the hidden-zone 404s: an echoed spelling would tell them apart.
    let lookup_name = normalize_zone_name(zone_name)?;
    db::zone::get_by_name(cx.db(), lookup_name.as_str())
        .await?
        .ok_or_else(|| ServiceError::zone_not_found(lookup_name.as_str()))
}

/// Fetch a zone by name for `caller` within the caller's transaction at
/// `lock_level`; a zone it cannot see reads as `NotFound`, so grants
/// cannot be probed. Visibility is decided on the row this tx locked, so
/// a same-name recreation cannot swap the zone in.
pub(crate) async fn get_visible_by_name_tx(
    tx: &mut Transaction<'_>,
    caller: &Caller,
    zone_name: &str,
    lock_level: LockLevel,
) -> Result<Zone, ServiceError> {
    let zone = get_by_name_tx(tx, zone_name, lock_level).await?;
    caller.authorize_zone_visible(&zone)?;
    Ok(zone)
}

/// Fetch a zone by name within the caller's transaction at `lock_level`,
/// returning `NotFound` if it does not exist.
pub(crate) async fn get_by_name_tx(
    tx: &mut Transaction<'_>,
    zone_name: &str,
    lock_level: LockLevel,
) -> Result<Zone, ServiceError> {
    let lookup_name = normalize_zone_name(zone_name)?;
    db::zone::get_by_name_tx(tx, lookup_name.as_str(), lock_level)
        .await?
        .ok_or_else(|| ServiceError::zone_not_found(lookup_name.as_str()))
}

/// Count both record planes for the IXFR/AXFR size comparison. These unlocked
/// counts may drift during a write; they choose the transfer format only.
pub async fn count_transfer_records(cx: &Context, zone_name: &str) -> Result<u64, ServiceError> {
    let records = db::record::count_by_filter(
        cx.db(),
        RecordFilter {
            zone_name: Some(zone_name.to_string()),
            ..RecordFilter::default()
        },
    )
    .await?;

    let dnssec_records = db::dnssec_record::count_by_filter(
        cx.db(),
        DnssecRecordFilter {
            zone_name: Some(zone_name.to_string()),
            ..DnssecRecordFilter::default()
        },
    )
    .await?;

    Ok(records + dnssec_records)
}
