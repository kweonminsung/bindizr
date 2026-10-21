use bindizr_core::{
    dns::name::OwnerName,
    model::{record::RecordId, role_grant::Action, zone::ZoneId},
};
use bindizr_db::Transaction;
use chrono::Utc;

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    serial::generate_serial,
    text::normalize_description,
    transaction,
    ttl::{normalize_minimum_ttl, normalize_soa_interval},
    types::{CreateZoneRequest, WriteZoneResponse, ZoneResponse},
    zone::validation::{normalize_name, normalize_soa, reject_catalog_zone_name},
};

/// Create a zone and NOTIFY the catalog; add an ordinary apex NS naming MNAME
/// unless opted out. Additional NS records are caller-managed.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateZoneRequest,
) -> Result<WriteZoneResponse, ServiceError> {
    caller.authorize_action(Action::ZoneCreate)?;

    // Parent/child zones are allowed; only the same normalized zone name is rejected.
    // Names are stored normalized, so an exact lookup is enough to detect a collision.
    let candidate = prepare_create(cx, request)?;
    let name = &candidate.name;

    match bindizr_db::zone::get_by_name(cx.db(), name).await {
        Ok(Some(_)) => {
            log::error!("Zone with name {} already exists", name);
            return Err(ServiceError::zone_conflict(format!(
                "zone with name '{}' already exists",
                name
            )));
        }
        Ok(None) => {}
        Err(error) => {
            log::error!("Failed to check existing zone: {}", error);
            return Err(ServiceError::internal_with_source(
                "failed to create zone",
                error,
            ));
        }
    };

    let mut tx = transaction::begin_tx(cx, "failed to create zone").await?;
    let apply_result: Result<_, ServiceError> = async {
        let caller = caller.reauthenticate_tx(&mut tx).await?;
        caller.authorize_action(Action::ZoneCreate)?;

        if request.dry_run {
            return Ok(candidate);
        }

        let created_zone = create_tx(&mut tx, candidate).await?;

        if request.apex_ns {
            let apex_ns = Record {
                id: RecordId::UNWRITTEN,
                name: OwnerName::apex(),
                record_type: RecordType::Ns,
                value: created_zone.mname.clone(),
                ttl: created_zone.default_ttl,
                priority: None,
                zone_id: created_zone.id,
                created_at: Utc::now(),
            };

            bindizr_db::record::create_many_tx(&mut tx, &[apex_ns]).await?;
        }

        super::save_version_tx(
            &mut tx,
            &created_zone,
            created_zone.serial,
            caller.change_origin(),
        )
        .await?;

        Ok(created_zone)
    }
    .await;
    let created_zone = transaction::finish_tx(tx, apply_result, "failed to create zone").await?;

    log::info!(
        "event=zone_create zone={} mname={} serial={} zone_id={} dry_run={}",
        created_zone.name,
        created_zone.mname,
        created_zone.serial,
        created_zone.id,
        request.dry_run
    );

    // Send catalog NOTIFY so secondaries pick up the new zone
    let config = cx.config();

    if !request.dry_run {
        cx.metrics().track_serial_bumps(1);
        if created_zone.enabled {
            crate::notify::notify_after_update(cx, &config.dns.catalog_zone_name).await;
        }
    }

    Ok(WriteZoneResponse {
        applied: !request.dry_run,
        dry_run: request.dry_run,
        zone: ZoneResponse::from(&created_zone),
    })
}

/// Resolve creation defaults once, before opening the transaction.
fn prepare_create(cx: &Context, request: &CreateZoneRequest) -> Result<Zone, ServiceError> {
    let name = normalize_name(&request.name)?;
    reject_catalog_zone_name(cx, &name)?;
    let defaults = &cx.config().dns.zone_defaults;
    let soa = normalize_soa(
        &request.mname,
        &request.rname,
        request.default_ttl.unwrap_or(i64::from(defaults.ttl)),
    )?;

    Ok(Zone {
        id: ZoneId::UNWRITTEN,
        name,
        mname: soa.mname,
        rname: soa.rname,
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: request.apex_ns,
        description: normalize_description(
            request.description.as_deref(),
            ServiceError::invalid_zone_field,
        )?,
        default_ttl: soa.ttl,
        serial: match request.serial {
            Some(serial) => serial,
            None => generate_serial(None),
        },
        refresh: normalize_soa_interval(request.refresh, defaults.refresh, "refresh")?,
        retry: normalize_soa_interval(request.retry, defaults.retry, "retry")?,
        expire: normalize_soa_interval(request.expire, defaults.expire, "expire")?,
        minimum_ttl: normalize_minimum_ttl(request.minimum_ttl, defaults.minimum_ttl)?,
        created_at: Utc::now(),
    })
}

/// Insert a prepared zone; the caller owns authorization, records and versioning.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_>,
    candidate: Zone,
) -> Result<Zone, ServiceError> {
    let name = candidate.name.clone();
    bindizr_db::zone::create_tx(tx, candidate)
        .await
        .map_err(|error| {
            if error.is_unique_violation() {
                ServiceError::zone_conflict(format!("zone with name '{}' already exists", name))
            } else {
                ServiceError::internal_with_source("failed to create zone", error)
            }
        })
}
