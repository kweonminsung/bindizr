use bindizr_core::{
    dns::{
        Serial,
        name::{OwnerName, ZoneName},
    },
    model::role_grant::Action,
};
use bindizr_db::LockLevel;

use crate::{
    Context,
    authorization::Caller,
    dnssec,
    error::ServiceError,
    model::{
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    record::validate_record_name_in_zone,
    serial::generate_serial,
    text::normalize_description,
    transaction,
    ttl::{validate_default_ttl, validate_soa_interval},
    types::{UpdateZoneRequest, WriteZoneResponse, ZoneResponse},
    zone::validation::{
        normalize_mname, normalize_name, normalize_rname, reject_catalog_zone_name,
    },
};

/// Outcome of the transactional part of a zone update.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateZoneResult {
    zone: Zone,
    /// Whether the update changed what the catalog publishes: its members are
    /// the enabled zones, listed by name.
    catalog_changed: bool,
}

/// DEL(old)+ADD(new) apex SOA changes for an in-place zone row update, so IXFR
/// consumers replay the SOA transition.
pub(crate) fn soa_replacement_changes(
    old_zone: &Zone,
    new_zone: &Zone,
    new_serial: Serial,
) -> Result<Vec<ZoneChange>, ServiceError> {
    let change = |operation: ChangeOperation, zone: &Zone| -> Result<ZoneChange, ServiceError> {
        Ok(ZoneChange {
            zone_id: old_zone.id,
            serial: new_serial,
            operation,
            record_name: OwnerName::apex(),
            record_type: JournalRecordType::Soa,
            record_value: Some(
                zone.soa_presentation_rdata()
                    .map_err(ServiceError::invalid_zone_field)?,
            ),
            record_rdata: None,
            record_ttl: zone.default_ttl,
            record_priority: None,
            derived: false,
        })
    };

    Ok(vec![
        change(ChangeOperation::Delete, old_zone)?,
        change(ChangeOperation::Add, new_zone)?,
    ])
}

/// Omitted fields keep the stored zone's value; the merge runs inside the
/// transaction, against the locked row.
pub async fn update(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    request: &UpdateZoneRequest,
) -> Result<WriteZoneResponse, ServiceError> {
    // Keep input errors until the locked zone has been authorized.
    let name = request
        .name
        .as_deref()
        .map(|name| {
            let name = normalize_name(name)?;
            reject_catalog_zone_name(cx, &name)?;
            Ok::<_, ServiceError>(name)
        })
        .transpose();
    let mname = request.mname.as_deref().map(normalize_mname).transpose();
    let rname = request.rname.as_deref().map(normalize_rname).transpose();
    let ttl = request.default_ttl.map(validate_default_ttl).transpose();
    let description = request
        .description
        .as_deref()
        .map(|description| {
            normalize_description(Some(description), ServiceError::invalid_zone_field)
        })
        .transpose();
    let refresh = request
        .refresh
        .map(|value| validate_soa_interval(value, "refresh"))
        .transpose();
    let retry = request
        .retry
        .map(|value| validate_soa_interval(value, "retry"))
        .transpose();
    let expire = request
        .expire
        .map(|value| validate_soa_interval(value, "expire"))
        .transpose();
    let minimum_ttl = request
        .minimum_ttl
        .map(|value| validate_soa_interval(value, "minimum_ttl"))
        .transpose();
    let mut tx = transaction::begin_tx(cx, "failed to update zone").await?;

    let apply_result: Result<UpdateZoneResult, ServiceError> = async {
        // Lock the zone row so the serial computed below stays ahead of
        // concurrent record mutations and nsupdate on the same zone.
        let existing_zone =
            super::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        caller.authorize_zone_action(Action::ZoneUpdate, &existing_zone)?;
        let zone_id = existing_zone.id;

        let candidate = Zone {
            name: name?.unwrap_or_else(|| existing_zone.name.clone()),
            mname: mname?.unwrap_or_else(|| existing_zone.mname.clone()),
            rname: rname?.unwrap_or_else(|| existing_zone.rname.clone()),
            default_ttl: ttl?.unwrap_or(existing_zone.default_ttl),
            description: description?.unwrap_or_else(|| existing_zone.description.clone()),
            refresh: refresh?.unwrap_or(existing_zone.refresh),
            retry: retry?.unwrap_or(existing_zone.retry),
            expire: expire?.unwrap_or(existing_zone.expire),
            minimum_ttl: minimum_ttl?.unwrap_or(existing_zone.minimum_ttl),
            serial: generate_serial(Some(existing_zone.serial)),
            enabled: request.enabled.unwrap_or(existing_zone.enabled),
            ..existing_zone.clone()
        };
        // A new name is `zone:create`'s to give, and its all-zones grant sees
        // all zones, so the conflict below reveals nothing.
        if candidate.name != existing_zone.name {
            caller.authorize_action(Action::ZoneCreate)?;
        }

        // A longer zone name lengthens every record's wire name, so the
        // records must still fit under it or the zone stops transferring.
        if candidate.name != existing_zone.name {
            let records =
                bindizr_db::record::list_tx(&mut tx, zone_id, LockLevel::Unlocked).await?;
            for record in &records {
                validate_record_name_in_zone(&record.name, &candidate.name).map_err(|e| {
                    if caller.sees_record(zone_id, &record.name, Some(&record.record_type)) {
                        e
                    } else {
                        ServiceError::invalid_record_name(format!(
                            "a record of the zone would not fit under zone '{}'",
                            candidate.name
                        ))
                    }
                })?;
            }
        }

        // Check rename conflicts without locks to avoid ordering deadlocks.
        // UNIQUE(name) catches races and maps to the same conflict.
        if candidate.name != existing_zone.name {
            match bindizr_db::zone::get_by_name(cx.db(), &candidate.name).await {
                Ok(Some(zone)) if zone.id != zone_id => {
                    log::error!("Zone with name {} already exists", candidate.name);
                    return Err(ServiceError::zone_conflict(format!(
                        "zone with name '{}' already exists",
                        candidate.name
                    )));
                }
                Ok(_) => {}
                Err(e) => {
                    log::error!("Failed to check existing zone: {}", e);
                    return Err(ServiceError::internal_with_source(
                        "failed to update zone",
                        e,
                    ));
                }
            }
        }

        let new_serial = candidate.serial;
        super::validate_record_changes_tx(&mut tx, &candidate, &[], &[]).await?;

        // The change is validated, so a dry run stops here.
        if request.dry_run {
            return Ok(UpdateZoneResult {
                zone: candidate,
                catalog_changed: false,
            });
        }

        let name = candidate.name.clone();
        let updated_zone = bindizr_db::zone::update_tx(&mut tx, candidate)
            .await
            .map_err(|e| {
                // A rename that raced past the pre-check above trips
                // UNIQUE(name); the backstop reads as the same conflict.
                if e.is_unique_violation() {
                    ServiceError::zone_conflict(format!("zone with name '{}' already exists", name))
                } else {
                    log::error!("Failed to update zone: {}", e);
                    ServiceError::internal_with_source("failed to update zone", e)
                }
            })?;

        // Journal the SOA and signature changes under the zone update's serial,
        // then save the version that future IXFR and rollback reads will use.
        let changes = soa_replacement_changes(&existing_zone, &updated_zone, new_serial)?;

        bindizr_db::zone_change::create_many_tx(&mut tx, &changes)
            .await
            .map_err(|e| {
                log::error!("Failed to create zone changes: {}", e);
                ServiceError::internal_with_source("failed to create zone change", e)
            })?;

        dnssec::sign_zone_tx(&mut tx, &updated_zone, new_serial).await?;
        super::save_version_tx(
            &mut tx,
            &updated_zone,
            new_serial,
            caller.change_attribution(),
        )
        .await?;

        Ok(UpdateZoneResult {
            catalog_changed: existing_zone.name != updated_zone.name
                || existing_zone.enabled != updated_zone.enabled,
            zone: updated_zone,
        })
    }
    .await;

    let UpdateZoneResult {
        zone: updated_zone,
        catalog_changed,
    } = transaction::finish_tx(tx, apply_result, "failed to update zone").await?;

    log::info!(
        "event=zone_update zone={} previous_name={} new_serial={} zone_id={} dry_run={}",
        updated_zone.name,
        zone_name,
        updated_zone.serial,
        updated_zone.id,
        request.dry_run
    );

    // Announce the zone's new serial after its data and version have committed.
    if !request.dry_run {
        cx.metrics().track_serial_bumps(1);
        crate::notify::notify_after_update(cx, &updated_zone.name).await;
    }

    // Renaming or toggling a zone also changes the catalog seen by secondaries.
    let config = cx.config();
    if !request.dry_run && catalog_changed {
        crate::notify::notify_after_update(cx, &config.dns.catalog_zone_name).await;
    }

    Ok(WriteZoneResponse {
        applied: !request.dry_run,
        dry_run: request.dry_run,
        zone: ZoneResponse::from(&updated_zone),
    })
}
