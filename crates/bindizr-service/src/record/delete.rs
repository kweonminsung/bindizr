use std::slice;

use bindizr_core::model::activity_log::ActivityOperation;
use bindizr_core::model::record::{Record, RecordId};
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::Zone;
use bindizr_db::LockLevel;

use crate::authorization::{Caller, RecordAccess};
use crate::error::ServiceError;
use crate::types::{
    DeleteRecordsRequest, DeleteRecordsResponse, RecordDiffResponse, RecordResponse, Run,
};
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
    let zone_id = bindizr_db::record::get(cx.db(), record_id)
        .await
        .map_err(|error| ServiceError::internal_with_source("failed to fetch record", error))?
        .ok_or_else(|| ServiceError::record_not_found(record_id))?
        .zone_id;

    let mut tx = transaction::begin_tx(cx, "failed to delete record").await?;

    let apply_result: Result<_, ServiceError> = async {
        let zone = bindizr_db::zone::get_tx(&mut tx, zone_id, LockLevel::Exclusive)
            .await
            .map_err(|error| ServiceError::internal_with_source("failed to fetch zone", error))?
            // The zone went with the record the request named.
            .ok_or_else(|| ServiceError::record_not_found(record_id))?;

        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        let existing_record = bindizr_db::record::get_tx(&mut tx, record_id)
            .await
            .map_err(|error| ServiceError::internal_with_source("failed to fetch record", error))?
            .filter(|record| record.zone_id == zone.id)
            .ok_or_else(|| ServiceError::record_not_found(record_id))?;

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

        let deleted = slice::from_ref(&existing_record);
        zone::validate_record_changes_tx(&mut tx, &zone, deleted, &[]).await?;

        // Only a preview carries the diff; the owner's rows frame it.
        let diff = if run.is_dry_run() {
            let records_at_name =
                bindizr_db::record::list_by_name_tx(&mut tx, zone.id, &existing_record.name)
                    .await?;
            let existing = caller
                .readable_records(records_at_name.into_iter().map(|record| (zone.id, record)));

            diff::build_record_preview(&zone, existing, deleted, [])
        } else {
            RecordDiffResponse::default()
        };

        let response = build_delete_response(&zone, caller, run, deleted, diff);

        if run.is_dry_run() {
            return Ok((response, zone.name));
        }

        let new_serial = serial::generate_serial(Some(zone.serial));
        record::delete_with_changes_tx(&mut tx, new_serial, deleted).await?;

        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;

        // Advance the serial once so IXFR consumers detect the change
        zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_origin()).await?;

        crate::activity::save_tx(
            &mut tx,
            ActivityOperation::RecordDelete,
            record::activity_target(&zone.name, &existing_record),
            caller.change_origin(),
        )
        .await?;

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
    let run = Run::from_dry_run(request.dry_run);
    let zone_name = zone::normalize_name(&request.zone_name)?;
    let owner = record::normalize_record_owner_name(&request.name, &zone_name)?;
    let record_type = request
        .record_type
        .as_deref()
        .map(record::parse_record_type)
        .transpose()?;

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

        // Encode the value as a create would, after checking that the caller
        // may delete at the supplied owner and type.
        let match_value = match (&request.value, record_type) {
            (Some(value), Some(record_type)) => Some(
                value
                    .to_encoded_value(record_type, request.priority)
                    .map_err(ServiceError::invalid_record_value)?,
            ),
            (Some(_), None) => {
                return Err(ServiceError::invalid_input(
                    "value narrows a record within one type, so type is required with it",
                ));
            }
            (None, _) => None,
        };

        let records_at_name = bindizr_db::record::list_by_name_tx(&mut tx, zone.id, &owner).await?;
        let matched: Vec<Record> = records_at_name
            .iter()
            .filter(|record| record.matches(record_type, match_value.as_deref(), request.priority))
            .cloned()
            .collect();

        zone::validate_record_changes_tx(&mut tx, &zone, &matched, &[]).await?;

        // Only a preview carries the diff; the owner's rows frame it.
        let diff = if run.is_dry_run() {
            let existing = caller
                .readable_records(records_at_name.into_iter().map(|record| (zone.id, record)));

            diff::build_record_preview(&zone, existing, &matched, [])
        } else {
            RecordDiffResponse::default()
        };

        let response = build_delete_response(&zone, caller, run, &matched, diff);
        if run.is_dry_run() || matched.is_empty() {
            return Ok(response);
        }

        // Apply the complete deletion and refresh signatures in the same transaction.
        let new_serial = serial::generate_serial(Some(zone.serial));
        record::delete_with_changes_tx(&mut tx, new_serial, &matched).await?;
        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;

        // Once for the whole set, so IXFR consumers see one step.
        zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_origin()).await?;

        crate::activity::save_many_tx(
            &mut tx,
            ActivityOperation::RecordDelete,
            matched
                .iter()
                .map(|record| record::activity_target(&zone.name, record))
                .collect(),
            caller.change_origin(),
        )
        .await?;

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

/// Project the deletion through the caller's read grants, while counting every matched row.
fn build_delete_response(
    zone: &Zone,
    caller: &Caller,
    run: Run,
    deleted: &[Record],
    diff: RecordDiffResponse,
) -> DeleteRecordsResponse {
    DeleteRecordsResponse {
        applied: !run.is_dry_run(),
        dry_run: run.is_dry_run(),
        deleted: deleted.len() as u64,
        records: caller
            .readable_records(deleted.iter().cloned().map(|record| (zone.id, record)))
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
        diff,
    }
}
