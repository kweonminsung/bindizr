use bindizr_core::model::zone::ZoneId;
use bindizr_db::Transaction;
use chrono::Utc;

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    model::zone::Zone,
    serial::{generate_serial, validate_initial_serial},
    transaction,
    types::{CreateZoneRequest, GetZoneResponse, ZoneWriteResponse},
    zone::validation::{ResolvedSoaTimers, normalize_create_zone_request, normalize_soa_timers},
};

/// Create a new zone and NOTIFY the catalog zone. The zone carries its
/// SOA and no records; its NS records are the caller's to add.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    create_zone_request: &CreateZoneRequest,
) -> Result<ZoneWriteResponse, ServiceError> {
    caller.authorize_global("create zones")?;

    // Parent/child zones are allowed; only the same normalized zone name is rejected.
    // Names are stored normalized, so an exact lookup is enough to detect a collision.
    let name = normalize_create_zone_request(cx, create_zone_request)?.name;
    match bindizr_db::zone::get_by_name(cx.db(), &name).await {
        Ok(Some(_)) => {
            log::error!("Zone with name {} already exists", name);
            return Err(ServiceError::zone_conflict(format!(
                "Zone with name '{}' already exists",
                name
            )));
        }
        Ok(None) => {}
        Err(e) => {
            log::error!("Failed to check existing zone: {}", e);
            return Err(ServiceError::internal("Failed to create zone"));
        }
    };

    let mut tx = transaction::begin_tx(cx, "Failed to create zone").await?;
    let apply_result = create_tx(cx, &mut tx, caller, create_zone_request).await;
    let created_zone = transaction::finish_tx(tx, apply_result, "Failed to create zone").await?;

    log::info!(
        "event=zone_create zone={} mname={} serial={} zone_id={}",
        created_zone.name,
        created_zone.mname,
        created_zone.serial,
        created_zone.id
    );

    // Send catalog NOTIFY so secondaries pick up the new zone
    let config = cx.config();
    if !create_zone_request.dry_run {
        crate::notify::notify_after_update(cx, &config.dns.catalog_zone_name).await;
    }

    Ok(ZoneWriteResponse {
        applied: !create_zone_request.dry_run,
        dry_run: create_zone_request.dry_run,
        zone: GetZoneResponse::from(&created_zone),
    })
}

/// Insert a zone and its first version on the caller's transaction, which
/// lets a zone import create and fill a zone in one transaction and a dry
/// run roll both back. [`create`] adds the duplicate pre-check and the
/// catalog NOTIFY after commit; here UNIQUE(name) is the whole check.
pub(crate) async fn create_tx(
    cx: &Context,
    tx: &mut Transaction<'_>,
    caller: &Caller,
    create_zone_request: &CreateZoneRequest,
) -> Result<Zone, ServiceError> {
    caller.authorize_global("create zones")?;

    let validated = normalize_create_zone_request(cx, create_zone_request)?;
    let defaults = &cx.config().dns.zone_defaults;
    let timers = normalize_soa_timers(
        create_zone_request,
        ResolvedSoaTimers {
            refresh: defaults.refresh,
            retry: defaults.retry,
            expire: defaults.expire,
            minimum_ttl: defaults.minimum_ttl,
        },
    )?;
    let serial = match create_zone_request.serial {
        Some(s) => validate_initial_serial(s)?,
        None => generate_serial(None)?,
    };

    let candidate = Zone {
        id: ZoneId::UNWRITTEN,
        name: validated.name,
        mname: validated.mname,
        rname: validated.rname,
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: validated.description.clone(),
        default_ttl: validated.ttl,
        serial,
        refresh: timers.refresh,
        retry: timers.retry,
        expire: timers.expire,
        minimum_ttl: timers.minimum_ttl,
        created_at: Utc::now(),
    };

    // The zone is validated, so a dry run stops before its first version.
    if create_zone_request.dry_run {
        return Ok(candidate);
    }

    let name = candidate.name.clone();
    let created_zone = bindizr_db::zone::create_tx(tx, candidate)
        .await
        .map_err(|e| {
            // A create that raced past a caller's pre-check trips UNIQUE(name);
            // the backstop reads as the same conflict.
            if e.is_unique_violation() {
                ServiceError::zone_conflict(format!("zone with name '{}' already exists", name))
            } else {
                log::error!("Failed to create zone: {}", e);
                ServiceError::internal("Failed to create zone")
            }
        })?;

    super::save_version_tx(
        cx,
        tx,
        &created_zone,
        created_zone.serial,
        &caller.change_subject(),
    )
    .await?;

    Ok(created_zone)
}
