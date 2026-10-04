use bindizr_core::model::{record::RecordId, role_grant::Action, zone::ZoneId};
use bindizr_db::Transaction;
use chrono::Utc;

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    model::{record::Record, zone::Zone},
    record::{PreparedRecord, normalize_record_owner_name, parse_record_request},
    serial::{generate_serial, validate_initial_serial},
    transaction,
    types::{CreateZoneRequest, GetZoneResponse, RecordValue, ZoneWriteResponse},
    zone::validation::{ResolvedSoaTimers, normalize_create_zone_request, normalize_soa_timers},
};

/// Create a new zone and NOTIFY the catalog zone. The zone carries its SOA
/// and, unless the request opts out, an apex NS record naming the MNAME, an
/// ordinary record from then on; further NS records are the caller's to add.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    create_zone_request: &CreateZoneRequest,
) -> Result<ZoneWriteResponse, ServiceError> {
    caller.authorize_action(Action::ZoneCreate)?;

    // Parent/child zones are allowed; only the same normalized zone name is rejected.
    // Names are stored normalized, so an exact lookup is enough to detect a collision.
    let name = normalize_create_zone_request(cx, create_zone_request)?.name;
    match bindizr_db::zone::get_by_name(cx.db(), &name).await {
        Ok(Some(_)) => {
            log::error!("Zone with name {} already exists", name);
            return Err(ServiceError::zone_conflict(format!(
                "zone with name '{}' already exists",
                name
            )));
        }
        Ok(None) => {}
        Err(e) => {
            log::error!("Failed to check existing zone: {}", e);
            return Err(ServiceError::internal_with_source(
                "failed to create zone",
                e,
            ));
        }
    };

    let mut tx = transaction::begin_tx(cx, "failed to create zone").await?;
    let apply_result = async {
        let caller = caller.reauthenticate_tx(&mut tx).await?;
        create_tx(&mut tx, cx, &caller, create_zone_request).await
    }
    .await;
    let created_zone = transaction::finish_tx(tx, apply_result, "failed to create zone").await?;

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

/// Insert a zone and its first version in the caller's transaction for atomic import or dry run.
/// UNIQUE(name) catches duplicates; [`create`] adds the pre-check and post-commit catalog NOTIFY.
/// `caller` holds the grants [`Caller::reauthenticate_tx`] reloaded in `tx`.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_>,
    cx: &Context,
    caller: &Caller,
    create_zone_request: &CreateZoneRequest,
) -> Result<Zone, ServiceError> {
    caller.authorize_action(Action::ZoneCreate)?;

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
                ServiceError::internal_with_source("failed to create zone", e)
            }
        })?;

    // The apex NS is born with the zone at its first serial, so it needs no
    // journal row: a secondary learns a new zone by AXFR.
    if create_zone_request.apex_ns {
        let PreparedRecord {
            record_type,
            value,
            priority,
            ..
        } = parse_record_request(
            "@",
            "NS",
            &RecordValue::Text(created_zone.mname.clone()),
            None,
            None,
        )?;
        let apex_ns = Record {
            id: RecordId::UNWRITTEN,
            name: normalize_record_owner_name("@", &created_zone.name)?,
            record_type,
            value,
            ttl: created_zone.default_ttl,
            priority,
            zone_id: created_zone.id,
            created_at: Utc::now(),
        };
        bindizr_db::record::create_many_tx(tx, &[apex_ns]).await?;
    }

    super::save_version_tx(
        tx,
        cx,
        &created_zone,
        created_zone.serial,
        caller.change_attribution(),
    )
    .await?;

    Ok(created_zone)
}
