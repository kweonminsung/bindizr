use std::collections::HashSet;
use std::slice;

use bindizr_core::model::record::{Record, RecordData, RecordId};
use bindizr_core::model::role_grant::Action;
use bindizr_db::LockLevel;

use crate::authorization::{Caller, RecordAccess};
use crate::error::ServiceError;
use crate::types::{DeleteRecordsRequest, DeleteRecordsResponse, RecordResponse, Run};
use crate::zone::diff;
use crate::{Context, dnssec, notify, record, serial, transaction, zone};

/// Delete a record by id, bumping the zone serial and recording a DEL
/// change for IXFR. `caller` is authorized against the row this tx locked.
/// A dry run answers with the filtered delete's preview and writes nothing.
pub async fn delete(
    cx: &Context,
    caller: &Caller,
    record_id: RecordId,
    run: Run,
) -> Result<DeleteRecordsResponse, ServiceError> {
    // Resolve zone_id with a non-locking read so the tx locks zone before
    // record (the create/bulk/import order); the reverse can deadlock.
    let zone_id = match bindizr_db::record::get(cx.db(), record_id).await {
        Ok(Some(record)) => record.zone_id,
        Ok(None) => return Err(ServiceError::record_not_found(record_id)),
        Err(error) => {
            return Err(ServiceError::internal_with_source(
                "failed to fetch record",
                error,
            ));
        }
    };

    let mut tx = transaction::begin_tx(cx, "failed to delete record").await?;

    let apply_result: Result<_, ServiceError> = async {
        let zone = match bindizr_db::zone::get_tx(&mut tx, zone_id, LockLevel::Exclusive).await {
            Ok(Some(zone)) => zone,
            // The zone went with the record the request named.
            Ok(None) => return Err(ServiceError::record_not_found(record_id)),
            Err(error) => {
                return Err(ServiceError::internal_with_source(
                    "failed to fetch zone",
                    error,
                ));
            }
        };

        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        let existing_record =
            match bindizr_db::record::get_tx(&mut tx, record_id, LockLevel::Exclusive).await {
                Ok(Some(record)) if record.zone_id == zone.id => record,
                Ok(Some(_) | None) => return Err(ServiceError::record_not_found(record_id)),
                Err(error) => {
                    return Err(ServiceError::internal_with_source(
                        "failed to fetch record",
                        error,
                    ));
                }
            };

        // A record the caller may neither read nor delete reads as 404, as
        // it does on GET, so ids cannot be probed.
        if !caller.reaches_record(
            Action::RecordDelete,
            zone.id,
            &existing_record.name,
            Some(existing_record.record_type),
        ) {
            return Err(ServiceError::record_not_found(record_id));
        }

        caller.authorize_record_access(
            &zone,
            &[RecordAccess {
                action: Action::RecordDelete,
                relative_name: existing_record.name.clone(),
                record_type: Some(existing_record.record_type),
            }],
        )?;

        // The owner's rows frame the diff, as they do for every change.
        let records_at_name = bindizr_db::record::list_by_name_tx(
            &mut tx,
            zone.id,
            &existing_record.name,
            LockLevel::Exclusive,
        )
        .await?;
        let before = caller.readable_records(
            zone.id,
            records_at_name.iter().cloned().map(RecordData::from),
        );
        let after = caller.readable_records(
            zone.id,
            records_at_name
                .iter()
                .filter(|record| record.id != existing_record.id)
                .cloned()
                .map(RecordData::from),
        );

        let response = DeleteRecordsResponse {
            applied: !run.is_dry_run(),
            dry_run: run.is_dry_run(),
            deleted: 1,
            // Only what the caller may read is listed back.
            records: caller
                .readable_records(zone.id, [existing_record.clone()])
                .as_slice()
                .iter()
                .map(|record| {
                    RecordResponse::from_record(
                        record,
                        &zone.name,
                        caller.record_actions(zone.id, &record.name, record.record_type),
                    )
                })
                .collect(),
            diff: diff::build_record_diff(&zone, &before, &after),
        };

        zone::validate_record_changes_tx(&mut tx, &zone, slice::from_ref(&existing_record), &[])
            .await?;

        let new_serial = serial::generate_serial(Some(zone.serial));

        if run.is_dry_run() {
            return Ok((response, zone.name));
        }

        record::delete_with_changes_tx(&mut tx, new_serial, slice::from_ref(&existing_record))
            .await?;

        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;

        // Advance the serial once so IXFR consumers detect the change
        zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_origin()).await?;

        Ok((response, zone.name))
    }
    .await;

    let (response, zone_name) =
        transaction::finish_tx(tx, apply_result, "failed to delete record").await?;

    log::info!(
        "event=record_delete zone={zone_name} record_id={record_id} applied={}",
        response.applied
    );

    // Announce only a committed deletion, never a preview.
    if response.applied {
        cx.metrics().track_serial_bumps(1);
        notify::notify_after_update(cx, &zone_name).await;
    }

    Ok(response)
}

/// Delete the selected records atomically, advancing the serial once
/// so secondaries cannot observe a partly removed set.
pub async fn delete_matching(
    cx: &Context,
    caller: &Caller,
    request: &DeleteRecordsRequest,
) -> Result<DeleteRecordsResponse, ServiceError> {
    let zone_name = zone::normalize_name(&request.zone_name)?;
    let owner = record::normalize_record_owner_name(&request.name, &zone_name)?;
    let record_type = request
        .record_type
        .as_deref()
        .map(record::parse_record_type)
        .transpose()?;

    if request.value.is_some() && record_type.is_none() {
        return Err(ServiceError::invalid_input(
            "value narrows a record within one type, so record_type is required with it",
        ));
    }

    // Encoded the way a create encodes it, so a value finds the row it made.
    let match_value = match (&request.value, record_type) {
        (Some(value), Some(record_type)) => Some(
            value
                .to_encoded_value(record_type, request.priority)
                .map_err(ServiceError::invalid_record_value)?,
        ),
        _ => None,
    };

    let mut tx = transaction::begin_tx(cx, "failed to delete records").await?;

    let apply_result: Result<_, ServiceError> = async {
        // Resolve matches and authorization under the zone lock, including previews.
        let zone = zone::lookup_by_name_tx(&mut tx, &zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        // Authorize the request, not the rows it matches: an answer that
        // depended on the match would reveal what lies outside the grant.
        caller.authorize_record_access(
            &zone,
            &[RecordAccess {
                action: Action::RecordDelete,
                relative_name: owner.clone(),
                record_type,
            }],
        )?;

        let records_at_name =
            bindizr_db::record::list_by_name_tx(&mut tx, zone.id, &owner, LockLevel::Exclusive)
                .await?;
        let matched: Vec<Record> = records_at_name
            .iter()
            .filter(|record| record.matches(record_type, match_value.as_deref(), request.priority))
            .cloned()
            .collect();

        // Build the preview from the validated rows; dry runs and empty matches
        // return it before any records or serials are written.
        let before = caller.readable_records(
            zone.id,
            records_at_name.iter().cloned().map(RecordData::from),
        );
        let deleted_ids: HashSet<RecordId> = matched.iter().map(|record| record.id).collect();
        let after = caller.readable_records(
            zone.id,
            records_at_name
                .iter()
                .filter(|record| !deleted_ids.contains(&record.id))
                .cloned()
                .map(RecordData::from),
        );

        let response = DeleteRecordsResponse {
            applied: !request.dry_run,
            dry_run: request.dry_run,
            deleted: matched.len() as u64,
            records: caller
                .readable_records(zone.id, matched.iter().cloned())
                .as_slice()
                .iter()
                .map(|record| {
                    RecordResponse::from_record(
                        record,
                        &zone.name,
                        caller.record_actions(zone.id, &record.name, record.record_type),
                    )
                })
                .collect(),
            diff: diff::build_record_diff(&zone, &before, &after),
        };

        zone::validate_record_changes_tx(&mut tx, &zone, &matched, &[]).await?;

        let new_serial = if matched.is_empty() {
            zone.serial
        } else {
            serial::generate_serial(Some(zone.serial))
        };

        if !response.applied || matched.is_empty() {
            return Ok(response);
        }

        // Apply the complete deletion and refresh signatures in the same transaction.
        record::delete_with_changes_tx(&mut tx, new_serial, &matched).await?;
        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;

        // Once for the whole set, so IXFR consumers see one step.
        zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_origin()).await?;

        Ok(response)
    }
    .await;

    let response = transaction::finish_tx(tx, apply_result, "failed to delete records").await?;

    log::info!(
        "event=record_delete_matching zone={zone_name} name={owner} type={record_type:?} deleted={} applied={}",
        response.deleted,
        response.applied
    );

    // Announce only a committed deletion, never a preview or an empty
    // match — which applies, but writes nothing and leaves the serial.
    if response.applied && response.deleted > 0 {
        cx.metrics().track_serial_bumps(1);
        notify::notify_after_update(cx, &zone_name).await;
    }

    Ok(response)
}
