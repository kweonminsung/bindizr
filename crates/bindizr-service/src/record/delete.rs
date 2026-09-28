use std::collections::HashSet;

use bindizr_core::{dns::name::OwnerName, model::record::RecordId};
use bindizr_db::LockLevel;

use super::validation::{normalize_record_owner_name, parse_record_type};
use crate::{
    Context,
    authorization::{Caller, RecordWrite},
    db, dnssec,
    error::ServiceError,
    model::record::{Record, RecordData},
    serial::generate_serial,
    transaction,
    types::{DeleteRecordsFilter, DeleteRecordsResponse, GetRecordResponse, Run},
    zone::{self, diff::build_record_diff, validation::normalize_zone_name},
};

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
    let zone_id = match db::record::get(cx.db(), record_id).await {
        Ok(Some(record)) => record.zone_id,
        Ok(None) => {
            return Err(ServiceError::record_not_found(record_id));
        }
        Err(e) => {
            log::error!("Failed to fetch record: {}", e);
            return Err(ServiceError::internal("Failed to fetch record"));
        }
    };

    let mut tx = transaction::begin_tx(cx, "Failed to delete record").await?;

    let apply_result: Result<DeleteRecordsResponse, ServiceError> = async {
        let zone = match db::zone::get_tx(&mut tx, zone_id, LockLevel::Exclusive).await {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                return Err(ServiceError::ZoneNotFound(format!(
                    "Zone with id '{}' not found",
                    zone_id
                )));
            }
            Err(e) => {
                log::error!("Failed to fetch zone: {}", e);
                return Err(ServiceError::internal("Failed to fetch zone"));
            }
        };

        let existing_record =
            match db::record::get_tx(&mut tx, record_id, LockLevel::Exclusive).await {
                Ok(Some(record)) if record.zone_id == zone.id => record,
                Ok(Some(_)) | Ok(None) => {
                    return Err(ServiceError::record_not_found(record_id));
                }
                Err(e) => {
                    log::error!("Failed to fetch record: {}", e);
                    return Err(ServiceError::internal("Failed to fetch record"));
                }
            };

        // A record the caller's grants do not reach reads as 404, as it
        // does on GET, so ids cannot be probed.
        if !caller.sees_record(
            zone.id,
            &existing_record.name,
            Some(&existing_record.record_type),
        ) {
            return Err(ServiceError::record_not_found(record_id));
        }
        caller
            .authorize_record_writes_tx(
                &mut tx,
                &zone,
                &[RecordWrite {
                    relative_name: existing_record.name.clone(),
                    record_type: Some(&existing_record.record_type),
                }],
            )
            .await?;

        // The owner's rows frame the diff, as they do for every change.
        let records_at_name = db::record::list_by_name_tx(
            &mut tx,
            zone.id,
            &existing_record.name,
            LockLevel::Exclusive,
        )
        .await?;
        let before: Vec<RecordData> = records_at_name
            .iter()
            .cloned()
            .map(RecordData::from)
            .collect();
        let after: Vec<RecordData> = records_at_name
            .iter()
            .filter(|record| record.id != existing_record.id)
            .cloned()
            .map(RecordData::from)
            .collect();

        let response = DeleteRecordsResponse {
            applied: !run.is_dry_run(),
            dry_run: run.is_dry_run(),
            deleted: 1,
            records: vec![GetRecordResponse::from_record_and_zone_name(
                &existing_record,
                &zone.name,
            )],
            diff: build_record_diff(&zone, &before, &after),
        };
        if run.is_dry_run() {
            return Ok(response);
        }

        let new_serial = generate_serial(Some(zone.serial))?;

        super::delete_with_changes_tx(
            &mut tx,
            zone.id,
            new_serial,
            std::slice::from_ref(&existing_record),
        )
        .await?;

        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
        // Advance the serial once so IXFR consumers detect the change
        zone::advance_serial_tx(cx, &mut tx, &zone, new_serial, &caller.change_subject()).await?;

        log::info!(
            "event=record_delete zone={} name={} type={} value={} record_id={}",
            zone.name,
            existing_record.name,
            existing_record.record_type,
            existing_record.value,
            existing_record.id
        );
        Ok(response)
    }
    .await;

    let response = transaction::finish_tx(tx, apply_result, "Failed to delete record").await?;

    // Announce only a committed deletion, never a preview.
    if response.applied
        && let Some(zone_name) = response.records.first().map(|record| &record.zone_name)
    {
        crate::notify::notify_after_update(cx, zone_name).await;
    }

    Ok(response)
}
/// Delete every record matching `filter` in one transaction. Row by row
/// would bump the serial once each and serve the half-removed set in
/// between.
pub async fn delete_matching(
    cx: &Context,
    caller: &Caller,
    filter: &DeleteRecordsFilter,
) -> Result<DeleteRecordsResponse, ServiceError> {
    let zone_name = normalize_zone_name(&filter.zone_name)?;
    let record_type = filter
        .record_type
        .as_deref()
        .map(parse_record_type)
        .transpose()?;
    if filter.value.is_some() && record_type.is_none() {
        return Err(ServiceError::invalid_input(
            "value narrows a record within one type, so record_type is required with it",
        ));
    }
    // Encoded the way a create encodes it, so a value finds the row it made.
    let match_value = match (&filter.value, record_type.as_ref()) {
        (Some(value), Some(record_type)) => Some(
            value
                .to_encoded_value(record_type, filter.priority)
                .map_err(ServiceError::invalid_input)?,
        ),
        _ => None,
    };

    let mut tx = transaction::begin_tx(cx, "Failed to delete records").await?;

    let result: Result<(DeleteRecordsResponse, OwnerName), ServiceError> = async {
        // Resolve matches and authorization under the zone lock, including previews.
        let zone =
            zone::get_visible_by_name_tx(&mut tx, caller, zone_name.as_str(), LockLevel::Exclusive)
                .await?;
        let owner = normalize_record_owner_name(&filter.name, &zone.name)?;

        // Authorize the request, not the rows it matches: an answer that
        // depended on the match would reveal what lies outside the grant.
        caller
            .authorize_record_writes_tx(
                &mut tx,
                &zone,
                &[RecordWrite {
                    relative_name: owner.clone(),
                    record_type: record_type.as_ref(),
                }],
            )
            .await?;

        let records_at_name =
            db::record::list_by_name_tx(&mut tx, zone.id, &owner, LockLevel::Exclusive).await?;
        let matched: Vec<Record> = records_at_name
            .iter()
            .filter(|record| {
                record.matches(
                    record_type.as_ref(),
                    match_value.as_deref(),
                    filter.priority,
                )
            })
            .cloned()
            .collect();

        // Build the preview from the validated rows; dry runs and empty matches
        // return it before any records or serials are written.
        let before: Vec<RecordData> = records_at_name
            .iter()
            .cloned()
            .map(RecordData::from)
            .collect();
        let removed: HashSet<RecordId> = matched.iter().map(|record| record.id).collect();
        let after: Vec<RecordData> = records_at_name
            .iter()
            .filter(|record| !removed.contains(&record.id))
            .cloned()
            .map(RecordData::from)
            .collect();

        let response = DeleteRecordsResponse {
            applied: !filter.dry_run,
            dry_run: filter.dry_run,
            deleted: matched.len() as u64,
            records: matched
                .iter()
                .map(|record| GetRecordResponse::from_record_and_zone_name(record, &zone.name))
                .collect(),
            diff: build_record_diff(&zone, &before, &after),
        };
        if !response.applied || matched.is_empty() {
            return Ok((response, owner));
        }

        // Apply the complete deletion and refresh signatures in the same transaction.
        let new_serial = generate_serial(Some(zone.serial))?;
        super::delete_with_changes_tx(&mut tx, zone.id, new_serial, &matched).await?;
        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
        // Once for the whole set, so IXFR consumers see one step.
        zone::advance_serial_tx(cx, &mut tx, &zone, new_serial, &caller.change_subject()).await?;

        Ok((response, owner))
    }
    .await;

    let (response, owner) = transaction::finish_tx(tx, result, "Failed to delete records").await?;

    log::info!(
        "event=record_delete_matching zone={} name={} type={:?} deleted={} applied={}",
        zone_name,
        owner,
        record_type,
        response.deleted,
        response.applied
    );

    // Announce only a committed deletion, never a preview or an empty
    // match — which applies, but writes nothing and leaves the serial.
    if response.applied && response.deleted > 0 {
        crate::notify::notify_after_update(cx, zone_name.as_str()).await;
    }

    Ok(response)
}
