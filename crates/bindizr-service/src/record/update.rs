use bindizr_core::{
    dns::name::ZoneName,
    model::{record::RecordId, role_grant::Action, zone::ZoneId},
};
use bindizr_db::LockLevel;

use super::validation::{
    normalize_record_owner_name, parse_record_type, validate_record_constraints,
};
use crate::{
    Context,
    authorization::{Caller, RecordAccess},
    dnssec,
    error::ServiceError,
    model::{
        record::{Record, RecordData, RecordType},
        zone::Zone,
    },
    serial::generate_serial,
    transaction,
    ttl::validate_record_ttl,
    types::{RecordDiffResponse, RecordResponse, UpdateRecordRequest, WriteRecordResponse},
    zone::{self, diff::build_record_diff},
};

/// The record an update locks: by id, with the zone the id form pre-read,
/// or by name.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
enum LockTarget<'a> {
    Id {
        record_id: RecordId,
        zone_id: ZoneId,
    },
    /// Several records at the name are an error: an update must not pick one
    /// of them on the caller's behalf.
    Name {
        zone_name: &'a ZoneName,
        name: &'a str,
    },
}

/// Resolve a replacement; omitted fields require read access to the stored record.
fn resolve_update(
    zone: &Zone,
    existing: &Record,
    request: &UpdateRecordRequest,
    can_read: bool,
) -> Result<Record, ServiceError> {
    let record_type = request
        .record_type
        .as_deref()
        .map(parse_record_type)
        .transpose();
    if !can_read {
        let mut missing = Vec::new();
        if request.name.is_none() {
            missing.push("name");
        }
        if request.record_type.is_none() {
            missing.push("type");
        }
        if request.value.is_none() {
            missing.push("value");
        }
        if request.ttl.is_none() {
            missing.push("ttl");
        }
        let takes_priority = record_type
            .as_ref()
            .ok()
            .and_then(|record_type| *record_type)
            .is_some_and(|record_type| matches!(record_type, RecordType::Mx | RecordType::Srv));
        if takes_priority && request.priority.is_none() {
            missing.push("priority");
        }
        if !missing.is_empty() {
            return Err(ServiceError::forbidden(format!(
                "an update without 'record:read' on the record must give every field; missing: {}",
                missing.join(", ")
            )));
        }
    }
    let record_type = record_type?.unwrap_or(existing.record_type);
    // Each type has its own stored grammar (TXT uses quoted presentation),
    // so a type change requires a fresh value.
    if record_type != existing.record_type && request.value.is_none() {
        return Err(ServiceError::invalid_input(
            "value is required when changing a record's type".to_string(),
        ));
    }
    // Reject explicit priority outside MX/SRV; changing away from them clears it.
    let priority = if matches!(record_type, RecordType::Mx | RecordType::Srv) {
        record_type.stored_priority(request.priority.or(existing.priority))
    } else if request.priority.is_some() {
        return Err(ServiceError::invalid_record_value(format!(
            "{} records do not take a priority",
            record_type
        )));
    } else {
        None
    };
    let encoded_value = match &request.value {
        Some(value) => value
            .to_encoded_value(&record_type, priority)
            .map_err(ServiceError::invalid_record_value)?,
        None => existing.value.clone(),
    };
    let ttl = match request.ttl {
        Some(ttl) => validate_record_ttl(ttl)?,
        None => existing.ttl,
    };
    // An omitted name keeps the stored owner, which needs no reparse.
    let owner_name = match &request.name {
        Some(name) => normalize_record_owner_name(name, &zone.name)?,
        None => existing.name.clone(),
    };
    Ok(Record {
        id: existing.id,
        name: owner_name,
        record_type,
        value: encoded_value,
        ttl,
        priority,
        zone_id: zone.id,
        created_at: existing.created_at,
    })
}

/// Merge omitted fields from the record loaded and authorized inside the transaction.
pub async fn update(
    cx: &Context,
    caller: &Caller,
    record_id: RecordId,
    request: &UpdateRecordRequest,
) -> Result<WriteRecordResponse, ServiceError> {
    // Non-locking read for the zone_id, so the tx locks zone before record
    // (the create/bulk/import order); the reverse can deadlock.
    let zone_id = match bindizr_db::record::get(cx.db(), record_id).await {
        Ok(Some(record)) => record.zone_id,
        Ok(None) => return Err(ServiceError::record_not_found(record_id)),
        Err(e) => {
            log::error!("Failed to fetch record: {}", e);
            return Err(ServiceError::internal_with_source(
                "failed to fetch record",
                e,
            ));
        }
    };
    update_locked(cx, caller, LockTarget::Id { record_id, zone_id }, request).await
}

/// Update the one record at `name` in `zone_name`. The match is resolved
/// under the zone lock, so the row written is the row that was counted.
pub async fn update_by_name(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    name: &str,
    request: &UpdateRecordRequest,
) -> Result<WriteRecordResponse, ServiceError> {
    update_locked(cx, caller, LockTarget::Name { zone_name, name }, request).await
}

/// Load the record inside the transaction, resolve the update against it,
/// then write it, bumping the zone serial and recording DEL+ADD IXFR changes.
async fn update_locked(
    cx: &Context,
    caller: &Caller,
    target: LockTarget<'_>,
    request: &UpdateRecordRequest,
) -> Result<WriteRecordResponse, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to update record").await?;

    let apply_result = async {
        let (zone, existing_record, caller) = match target {
            LockTarget::Id { record_id, zone_id } => {
                let zone =
                    match bindizr_db::zone::get_tx(&mut tx, zone_id, LockLevel::Exclusive).await {
                        Ok(Some(zone)) => zone,
                        Ok(None) => {
                            return Err(ServiceError::ZoneNotFound(format!(
                                "zone with id '{}' not found",
                                zone_id
                            )));
                        }
                        Err(e) => {
                            log::error!("Failed to fetch zone: {}", e);
                            return Err(ServiceError::internal_with_source(
                                "failed to fetch zone",
                                e,
                            ));
                        }
                    };
                let caller = caller.reauthenticate_tx(&mut tx).await?;

                let existing_record = match bindizr_db::record::get_tx(
                    &mut tx,
                    record_id,
                    LockLevel::Exclusive,
                )
                .await
                {
                    Ok(Some(record)) if record.zone_id == zone.id => record,
                    Ok(Some(_)) | Ok(None) => {
                        return Err(ServiceError::record_not_found(record_id));
                    }
                    Err(e) => {
                        log::error!("Failed to fetch record: {}", e);
                        return Err(ServiceError::internal_with_source(
                            "failed to fetch record",
                            e,
                        ));
                    }
                };

                // A record the caller may neither read nor update reads as
                // 404, as it does on GET, so ids cannot be probed.
                if !caller.reaches_record(
                    Action::RecordUpdate,
                    zone.id,
                    &existing_record.name,
                    Some(&existing_record.record_type),
                ) {
                    return Err(ServiceError::record_not_found(record_id));
                }

                (zone, existing_record, caller)
            }
            LockTarget::Name { zone_name, name } => {
                let zone =
                    zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
                let caller = caller.reauthenticate_tx(&mut tx).await?;
                caller.authorize_zone_visible(&zone)?;
                let owner = normalize_record_owner_name(name, &zone.name)?;

                // Count only what the caller may read or update.
                let mut matched: Vec<Record> = bindizr_db::record::list_by_name_tx(
                    &mut tx,
                    zone.id,
                    &owner,
                    LockLevel::Exclusive,
                )
                .await?
                .into_iter()
                .filter(|record| {
                    caller.reaches_record(
                        Action::RecordUpdate,
                        zone.id,
                        &record.name,
                        Some(&record.record_type),
                    )
                })
                .collect();

                match matched.len() {
                    1 => (zone, matched.remove(0), caller),
                    0 => {
                        return Err(ServiceError::record_not_found_at_name(&zone.name, &owner));
                    }
                    matches => {
                        return Err(ServiceError::record_name_ambiguous(
                            &zone.name, &owner, matches,
                        ));
                    }
                }
            }
        };

        let caller = &caller;

        // Inheriting an omitted field reads the record.
        let can_read = caller.sees_record(
            zone.id,
            &existing_record.name,
            Some(&existing_record.record_type),
        );
        let candidate = resolve_update(&zone, &existing_record, request, can_read)?;

        // An update moves a record from its stored identity to the requested
        // one, so `record:update` must reach both.
        caller.authorize_record_access(
            &zone,
            &[
                RecordAccess {
                    action: Action::RecordUpdate,
                    relative_name: existing_record.name.clone(),
                    record_type: Some(&existing_record.record_type),
                },
                RecordAccess {
                    action: Action::RecordUpdate,
                    relative_name: candidate.name.clone(),
                    record_type: Some(&candidate.record_type),
                },
            ],
        )?;
        // Only records sharing the new owner name can conflict, so load just
        // those instead of the whole zone.
        let records_at_name = match bindizr_db::record::list_by_name_tx(
            &mut tx,
            zone.id,
            &candidate.name,
            LockLevel::Exclusive,
        )
        .await
        {
            Ok(records) => records,
            Err(e) => {
                log::error!("Failed to load records: {}", e);
                return Err(ServiceError::internal_with_source(
                    "failed to update record",
                    e,
                ));
            }
        };

        validate_record_constraints(
            &records_at_name,
            &candidate.name,
            &candidate.record_type,
            &candidate.value,
            candidate.ttl,
            candidate.priority,
            Some(existing_record.id),
        )?;

        // The owner's rows frame the diff. A move spans two, and the record
        // sits at the one it leaves, so that name's rows come along too.
        let mut framed = records_at_name.clone();
        if candidate.name != existing_record.name {
            framed.extend(
                bindizr_db::record::list_by_name_tx(
                    &mut tx,
                    zone.id,
                    &existing_record.name,
                    LockLevel::Exclusive,
                )
                .await?,
            );
        }
        let before = caller.readable_records(zone.id, framed.iter().cloned().map(RecordData::from));
        let mut after = caller.readable_records(
            zone.id,
            framed
                .iter()
                .filter(|record| record.id != existing_record.id)
                .cloned()
                .map(RecordData::from),
        );
        after.push_written(RecordData::from(candidate.clone()));
        let diff = build_record_diff(&zone, &before, &after);

        zone::validate_record_changes_tx(
            &mut tx,
            &zone,
            std::slice::from_ref(&existing_record),
            std::slice::from_ref(&candidate),
        )
        .await?;

        let new_serial = generate_serial(Some(zone.serial))?;

        // The merge is resolved and validated, so a dry run stops here.
        if request.dry_run {
            return Ok::<(Record, ZoneName, RecordDiffResponse), ServiceError>((
                candidate, zone.name, diff,
            ));
        }

        // Store the validated replacement, signatures, and journal under one serial.
        let zone_name = zone.name.clone();

        let updated_record =
            super::update_with_changes_tx(&mut tx, new_serial, &existing_record, candidate).await?;

        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
        // Advance the serial once so IXFR consumers detect the change
        zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_attribution()).await?;

        Ok::<(Record, ZoneName, RecordDiffResponse), ServiceError>((
            updated_record,
            zone_name,
            diff,
        ))
    }
    .await;

    let (updated_record, zone_name, diff) =
        transaction::finish_tx(tx, apply_result, "failed to update record").await?;

    log::info!(
        "event=record_update zone={} name={} type={} ttl={} priority={} record_id={} dry_run={}",
        zone_name,
        updated_record.name,
        updated_record.record_type,
        updated_record.ttl,
        updated_record
            .priority
            .map_or("null".to_string(), |v| v.to_string()),
        updated_record.id,
        request.dry_run
    );

    // Request secondary transfers only after the replacement is committed.
    if !request.dry_run {
        cx.metrics().track_serial_bumps(1);
        crate::notify::notify_after_update(cx, &zone_name).await;
    }

    Ok(WriteRecordResponse {
        applied: !request.dry_run,
        dry_run: request.dry_run,
        record: RecordResponse::from_record(
            &updated_record,
            &zone_name,
            caller.record_actions(
                updated_record.zone_id,
                &updated_record.name,
                &updated_record.record_type,
            ),
        ),
        diff,
    })
}
