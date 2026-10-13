use bindizr_core::{
    dns::name::ZoneName,
    model::{record::RecordId, role_grant::Action},
};
use bindizr_db::LockLevel;
use chrono::Utc;

use super::validation::{
    ParsedRecord, normalize_record_owner_name, parse_record_fields, validate_record_constraints,
};
use crate::{
    Context,
    authorization::{Caller, RecordAccess},
    dnssec,
    error::ServiceError,
    model::record::{Record, RecordData},
    serial::generate_serial,
    transaction,
    types::{CreateRecordRequest, RecordDiffResponse, RecordResponse, WriteRecordResponse},
    zone::{self, diff::build_record_diff},
};

/// Create a record, bumping the zone serial and recording an ADD change
/// for IXFR. `caller` is authorized against the zone this tx locked.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    create_record_request: &CreateRecordRequest,
) -> Result<WriteRecordResponse, ServiceError> {
    let ParsedRecord {
        record_type,
        value: record_value,
        priority,
        ttl,
    } = parse_record_fields(
        &create_record_request.record_type,
        &create_record_request.value,
        create_record_request.ttl,
        create_record_request.priority,
    )?;

    let zone_name = zone::normalize_name(&create_record_request.zone_name)?;
    let owner_name = normalize_record_owner_name(&create_record_request.name, &zone_name)?;
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
            Err(e) => {
                log::error!("Failed to check existing records: {}", e);
                return Err(ServiceError::internal_with_source(
                    "failed to create record",
                    e,
                ));
            }
        };

        // Fixed at write time: a later zone TTL change will not move it.
        let ttl = ttl.unwrap_or(zone.default_ttl);

        validate_record_constraints(
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
        let diff = build_record_diff(&zone, &before, &after);

        let new_serial = generate_serial(Some(zone.serial))?;

        // The record is validated and authorized, so a dry run stops here.
        if create_record_request.dry_run {
            return Ok::<(Record, ZoneName, RecordDiffResponse), ServiceError>((
                candidate, zone.name, diff,
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
        zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_attribution()).await?;

        Ok::<(Record, ZoneName, RecordDiffResponse), ServiceError>((
            created_record,
            zone.name,
            diff,
        ))
    }
    .await;

    let (created_record, zone_name, diff) =
        transaction::finish_tx(tx, apply_result, "failed to create record").await?;

    log::info!(
        "event=record_create dry_run={} zone={} name={} type={} ttl={} priority={} record_id={}",
        create_record_request.dry_run,
        zone_name,
        created_record.name,
        created_record.record_type,
        created_record.ttl,
        created_record
            .priority
            .map_or("null".to_string(), |v| v.to_string()),
        created_record.id
    );

    // Request secondary transfers only after the new record is committed.
    if !create_record_request.dry_run {
        cx.metrics().track_serial_bumps(1);
        crate::notify::notify_after_update(cx, &zone_name).await;
    }

    Ok(WriteRecordResponse {
        applied: !create_record_request.dry_run,
        dry_run: create_record_request.dry_run,
        record: RecordResponse::from_record(
            &created_record,
            &zone_name,
            caller.record_actions(
                created_record.zone_id,
                &created_record.name,
                &created_record.record_type,
            ),
        ),
        diff,
    })
}
