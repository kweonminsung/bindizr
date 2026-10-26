use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::record::RecordId;
use bindizr_core::model::role_grant::Action;
use bindizr_db::LockLevel;
use chrono::Utc;

use super::validation;
use super::validation::ParsedRecord;
use crate::authorization::{Caller, RecordAccess};
use crate::error::ServiceError;
use crate::model::record::{Record, RecordData};
use crate::types::{CreateRecordRequest, RecordDiffResponse, RecordResponse, WriteRecordResponse};
use crate::zone::diff;
use crate::{Context, dnssec, serial, transaction, zone};

/// Create a record, bumping the zone serial and recording an ADD change
/// for IXFR. `caller` is authorized against the zone this tx locked.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateRecordRequest,
) -> Result<WriteRecordResponse, ServiceError> {
    let ParsedRecord {
        record_type,
        value: record_value,
        priority,
        ttl,
    } = validation::parse_record_fields(
        &request.record_type,
        &request.value,
        request.ttl,
        request.priority,
    )?;

    let zone_name = zone::normalize_name(&request.zone_name)?;
    let owner_name = validation::normalize_record_owner_name(&request.name, &zone_name)?;

    let mut tx = transaction::begin_tx(cx, "failed to create record").await?;

    let apply_result = async {
        let zone = zone::lookup_by_name_tx(&mut tx, &zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        caller.authorize_record_access(
            &zone,
            &[RecordAccess {
                action: Action::RecordCreate,
                relative_name: owner_name.clone(),
                record_type: Some(&record_type),
            }],
        )?;

        // Only records sharing the owner name can conflict, so load just
        // those instead of the whole zone.
        let records_at_name = match bindizr_db::record::list_by_name_tx(
            &mut tx,
            zone.id,
            &owner_name,
            LockLevel::Exclusive,
        )
        .await
        {
            Ok(records) => records,
            Err(error) => {
                log::error!("Failed to check existing records: {}", error);
                return Err(ServiceError::internal_with_source(
                    "failed to create record",
                    error,
                ));
            }
        };

        // Fixed at write time: a later zone TTL change will not move it.
        let ttl = ttl.unwrap_or(zone.default_ttl);

        validation::validate_record_constraints(
            &records_at_name,
            &owner_name,
            &record_type,
            &record_value,
            ttl,
            priority,
            None,
        )?;

        // The owner's rows frame the diff, as they do for every change.
        let before = caller.readable_records(
            zone.id,
            records_at_name.iter().cloned().map(RecordData::from),
        );
        let candidate = Record {
            id: RecordId::UNWRITTEN,
            name: owner_name,
            record_type,
            value: record_value,
            ttl,
            priority,
            zone_id: zone.id,
            created_at: Utc::now(),
        };

        zone::validate_record_changes_tx(&mut tx, &zone, &[], std::slice::from_ref(&candidate))
            .await?;

        let mut after = before.clone();
        after.push_written(RecordData::from(candidate.clone()));
        let diff = diff::build_record_diff(&zone, &before, &after);

        let new_serial = serial::generate_serial(Some(zone.serial));
        let actions = caller.record_actions(zone.id, &candidate.name, &candidate.record_type);

        // The record is validated and authorized, so a dry run stops here.
        if request.dry_run {
            return Ok::<(Record, ZoneName, RecordDiffResponse, Vec<Action>), ServiceError>((
                candidate, zone.name, diff, actions,
            ));
        }

        // Persist the validated record and its signed view as one journaled serial.
        let created_record = super::create_with_changes_tx(
            &mut tx,
            zone.id,
            new_serial,
            std::slice::from_ref(&candidate),
        )
        .await?
        .pop()
        .ok_or_else(|| {
            log::error!("Record insert returned no row");
            ServiceError::internal("record insert returned no row")
        })?;

        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;

        // Advance the serial once so IXFR consumers detect the change
        zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_origin()).await?;

        Ok::<(Record, ZoneName, RecordDiffResponse, Vec<Action>), ServiceError>((
            created_record,
            zone.name,
            diff,
            actions,
        ))
    }
    .await;

    let (created_record, zone_name, diff, actions) =
        transaction::finish_tx(tx, apply_result, "failed to create record").await?;

    log::info!(
        "event=record_create dry_run={} zone={} name={} type={} ttl={} priority={} record_id={}",
        request.dry_run,
        zone_name,
        created_record.name,
        created_record.record_type,
        created_record.ttl,
        created_record
            .priority
            .map_or("null".to_string(), |value| value.to_string()),
        created_record.id
    );

    // Request secondary transfers only after the new record is committed.
    if !request.dry_run {
        cx.metrics().track_serial_bumps(1);
        crate::notify::notify_after_update(cx, &zone_name).await;
    }

    Ok(WriteRecordResponse {
        applied: !request.dry_run,
        dry_run: request.dry_run,
        record: RecordResponse::from_record(&created_record, &zone_name, actions),
        diff,
    })
}
