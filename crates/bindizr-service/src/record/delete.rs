use std::collections::HashSet;

use bindizr_core::dns::name::OwnerName;
use bindizr_db::repository::LockLevel;

use super::{
    RecordService, matches_record,
    validation::{normalize_record_owner_name, parse_record_type},
};
use crate::{
    authorization::{Caller, RecordWrite},
    dnssec::DnssecService,
    error::{ErrorCode, ServiceError},
    model::record::{Record, RecordData},
    repository::RepositoryService,
    serial::generate_serial,
    types::{DeleteRecordsFilter, DeleteRecordsResponse, GetRecordResponse},
    zone::{ZoneService, diff::build_record_diff, validation::normalize_zone_name},
};

impl RecordService {
    /// Delete a record by id, bumping the zone serial and recording a DEL
    /// change for IXFR. `caller` is authorized inside the delete transaction,
    /// so a concurrent rename cannot outrun the check. A dry run answers with
    /// the same preview the filtered delete builds and writes nothing.
    pub async fn delete(
        caller: &Caller,
        record_id: i32,
        dry_run: bool,
    ) -> Result<DeleteRecordsResponse, ServiceError> {
        // Resolve zone_id with a non-locking read so the tx locks zone before
        // record (the create/bulk/import order); the reverse can deadlock.
        let zone_id = match RepositoryService::get_record(record_id).await {
            Ok(Some(record)) => record.zone_id,
            Ok(None) => {
                return Err(ServiceError::record_not_found(record_id));
            }
            Err(e) => {
                log::error!("Failed to fetch record: {}", e);
                return Err(ServiceError::internal("Failed to fetch record"));
            }
        };

        let mut tx = RepositoryService::begin_tx("Failed to delete record").await?;

        let apply_result: Result<DeleteRecordsResponse, ServiceError> = async {
            let zone = match RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::Exclusive)
                .await
            {
                Ok(Some(zone)) => zone,
                Ok(None) => {
                    return Err(ServiceError::new(
                        ErrorCode::ZoneNotFound,
                        format!("Zone with id '{}' not found", zone_id),
                    ));
                }
                Err(e) => {
                    log::error!("Failed to fetch zone: {}", e);
                    return Err(ServiceError::internal("Failed to fetch zone"));
                }
            };

            let existing_record =
                match RepositoryService::get_record_tx(&mut tx, record_id, LockLevel::Exclusive)
                    .await
                {
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
            let records_at_name = RepositoryService::list_records_by_name_tx(
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
                applied: !dry_run,
                dry_run,
                deleted: 1,
                records: vec![GetRecordResponse::from_record_and_zone_name(
                    &existing_record,
                    &zone.name,
                )],
                diff: build_record_diff(&zone, &before, &after),
            };
            if dry_run {
                return Ok(response);
            }

            let new_serial = generate_serial(Some(zone.serial))?;

            Self::delete_with_changes_tx(
                &mut tx,
                zone.id,
                new_serial,
                std::slice::from_ref(&existing_record),
            )
            .await?;

            DnssecService::sign_zone_tx(&mut tx, &zone, new_serial).await?;
            // Advance the serial once so IXFR consumers detect the change
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial, &caller.change_subject())
                .await?;

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

        let response =
            RepositoryService::finish_tx(tx, apply_result, "Failed to delete record").await?;

        // Announce only a committed deletion, never a preview.
        if response.applied
            && let Some(zone_name) = response.records.first().map(|record| &record.zone_name)
            && let Err(e) = crate::notify::send_notify_after_update(Some(zone_name.as_str())).await
        {
            log::warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(response)
    }
    /// Delete every record matching `filter` in one transaction. Row by row
    /// would bump the serial once each and serve the half-removed set in
    /// between.
    pub async fn delete_matching(
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

        let mut tx = RepositoryService::begin_tx("Failed to delete records").await?;

        let result: Result<(DeleteRecordsResponse, OwnerName), ServiceError> = async {
            // Resolve matches and authorization under the zone lock, including previews.
            let zone = ZoneService::get_visible_by_name_tx(
                &mut tx,
                caller,
                zone_name.as_str(),
                LockLevel::Exclusive,
            )
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

            let records_at_name = RepositoryService::list_records_by_name_tx(
                &mut tx,
                zone.id,
                &owner,
                LockLevel::Exclusive,
            )
            .await?;
            let matched: Vec<Record> = records_at_name
                .iter()
                .filter(|record| {
                    matches_record(
                        record,
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
            let removed: HashSet<i32> = matched.iter().map(|record| record.id).collect();
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
            Self::delete_with_changes_tx(&mut tx, zone.id, new_serial, &matched).await?;
            DnssecService::sign_zone_tx(&mut tx, &zone, new_serial).await?;
            // Once for the whole set, so IXFR consumers see one step.
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial, &caller.change_subject())
                .await?;

            Ok((response, owner))
        }
        .await;

        let (response, owner) =
            RepositoryService::finish_tx(tx, result, "Failed to delete records").await?;

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
        if response.applied
            && response.deleted > 0
            && let Err(e) = crate::notify::send_notify_after_update(Some(zone_name.as_str())).await
        {
            log::warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(response)
    }
}
