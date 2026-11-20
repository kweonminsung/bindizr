use std::collections::HashMap;
use std::time::Instant;

use bindizr_core::dns::name::OwnerName;
use bindizr_core::model::record::{Record, RecordData, RecordId};
use bindizr_core::model::role_grant::Action;
use bindizr_db::LockLevel;
use chrono::Utc;

use crate::authorization::{Caller, RecordAccess};
use crate::error::ServiceError;
use crate::record::validation;
use crate::types::{
    CreateBulkRecordsRequest, CreateBulkRecordsResponse, RecordDiffResponse, RecordResponse,
};
use crate::zone::diff;
use crate::{Context, dnssec, notify, record, serial, time, transaction, zone};

/// Per-stage timings, emitted as one debug summary after commit + NOTIFY.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
struct BulkTimings {
    load_zone_ms: f64,
    load_existing_ms: f64,
    build_index_ms: f64,
    build_records_ms: f64,
    db_write_ms: f64,
    serial_ms: f64,
}

/// Insert records atomically after locking and authorizing the zone, with one serial,
/// version, and post-commit NOTIFY; a dry run validates and returns the proposed rows.
pub async fn create_bulk(
    cx: &Context,
    caller: &Caller,
    request: &CreateBulkRecordsRequest,
) -> Result<CreateBulkRecordsResponse, ServiceError> {
    let zone_name = zone::normalize_name(&request.zone_name)?;
    let records = &request.records;

    if records.is_empty() {
        return Err(ServiceError::invalid_input(
            "no records provided for bulk insert",
        ));
    }

    let total_started = Instant::now();

    // Validate types and values up front so a malformed record fails fast.
    let started = Instant::now();
    let prepared = records
        .iter()
        .map(|record| {
            validation::parse_record_fields(
                &record.record_type,
                &record.value,
                record.ttl,
                record.priority,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let owners: Vec<_> = records
        .iter()
        .map(|record| validation::normalize_record_owner_name(&record.name, &zone_name))
        .collect();
    let prepare_ms = time::elapsed_ms(started);

    let mut timings = BulkTimings::default();

    let mut tx = transaction::begin_tx(cx, "failed to create records").await?;

    let apply_result: Result<_, ServiceError> = async {
        let started = Instant::now();

        let zone = zone::lookup_by_name_tx(&mut tx, &zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        timings.load_zone_ms = time::elapsed_ms(started);

        // Authorize before loading existing record rows so an ungranted caller
        // gets 404 instead of constraint details; dry runs included.
        // A name that will not parse lists no write; validation reports it.
        let writes: Vec<RecordAccess> = prepared
            .iter()
            .zip(&owners)
            .filter_map(|(prepared_record, owner)| {
                owner.as_ref().ok().map(|owner| RecordAccess {
                    action: Action::RecordCreate,
                    relative_name: owner.clone(),
                    record_type: Some(prepared_record.record_type),
                })
            })
            .collect();
        caller.authorize_record_access(&zone, &writes)?;

        // Only records whose owner name appears in the batch can conflict, so
        // load just those instead of the whole zone.
        let started = Instant::now();
        let mut batch_owners: Vec<OwnerName> = writes
            .iter()
            .map(|write| write.relative_name.clone())
            .collect();
        batch_owners.sort();
        batch_owners.dedup();

        let existing_records = bindizr_db::record::list_by_names_tx(
            &mut tx,
            zone.id,
            &batch_owners,
            LockLevel::Exclusive,
        )
        .await
        .map_err(|error| ServiceError::internal_with_source("failed to create records", error))?;

        timings.load_existing_ms = time::elapsed_ms(started);

        let new_serial = serial::generate_serial(Some(zone.serial));

        // The diff is only shown on a dry-run preview, so keep the `before`
        // copy (and pay for building the diff) off the apply hot path.
        let before_records = if request.dry_run {
            existing_records.clone()
        } else {
            Vec::new()
        };

        // Index by owner to limit conflict scans while including earlier batch additions.
        let started = Instant::now();
        let mut records_by_name: HashMap<OwnerName, Vec<Record>> =
            HashMap::with_capacity(existing_records.len());

        for record in existing_records {
            records_by_name
                .entry(record.name.clone())
                .or_default()
                .push(record);
        }

        timings.build_index_ms = time::elapsed_ms(started);

        let started = Instant::now();
        let mut to_insert = Vec::with_capacity(prepared.len());

        for (prepared_record, owner) in prepared.iter().zip(owners) {
            let owner = owner?;

            let records_at_name = records_by_name.entry(owner.clone()).or_default();

            // Fixed at write time: a later zone TTL change will not move it.
            let ttl = prepared_record.ttl.unwrap_or(zone.default_ttl);

            validation::validate_record_constraints(
                records_at_name,
                &owner,
                prepared_record.record_type,
                &prepared_record.value,
                ttl,
                prepared_record.priority,
                None,
            )?;

            let record = Record {
                id: RecordId::UNWRITTEN,
                name: owner,
                record_type: prepared_record.record_type,
                value: prepared_record.value.clone(),
                ttl,
                priority: prepared_record.priority,
                zone_id: zone.id,
                created_at: Utc::now(),
            };
            records_at_name.push(record.clone());
            to_insert.push(record);
        }

        timings.build_records_ms = time::elapsed_ms(started);

        zone::validate_record_changes_tx(&mut tx, &zone, &[], &to_insert).await?;

        let (created_records, diff) = if request.dry_run {
            // `after` = existing plus the inserts, so an insert into an
            // existing record set reads as `changed`, not a bare `added`.
            let before =
                caller.readable_records(zone.id, before_records.into_iter().map(RecordData::from));
            let mut after = before.clone();

            for record in &to_insert {
                after.push_written(RecordData::from(record.clone()));
            }

            let diff = diff::build_record_diff(&zone, &before, &after);

            (to_insert, diff)
        } else {
            let started = Instant::now();

            let created_records =
                record::create_with_changes_tx(&mut tx, zone.id, new_serial, &to_insert).await?;

            timings.db_write_ms = time::elapsed_ms(started);

            let started = Instant::now();

            dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;

            // Advance the serial once so IXFR consumers detect the batch.
            zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_origin()).await?;

            timings.serial_ms = time::elapsed_ms(started);

            (created_records, RecordDiffResponse::default())
        };

        // Carry grants out of the locked snapshot; render values after commit.
        let records: Vec<_> = created_records
            .into_iter()
            .map(|record| {
                let actions =
                    caller.record_actions(record.zone_id, &record.name, record.record_type);
                (record, actions)
            })
            .collect();

        Ok((records, zone.name, diff))
    }
    .await;

    let (created_records, zone_name, diff) =
        transaction::finish_tx(tx, apply_result, "failed to create records").await?;

    log::info!(
        "event=record_bulk_create zone={zone_name} count={} dry_run={}",
        created_records.len(),
        request.dry_run
    );

    let started = Instant::now();

    if !request.dry_run {
        cx.metrics().track_serial_bumps(1);
        notify::notify_after_update(cx, &zone_name).await;
    }

    let notify_ms = time::elapsed_ms(started);

    // Per-stage breakdown for profiling; debug-gated so it stays out of
    // normal (info-level) runs. NOTIFY is inline only in sync apply mode.
    log::debug!(
        "event=record_bulk_create_timing zone={zone_name} count={} prepare_ms={prepare_ms:.1} load_zone_ms={:.1} \
         load_existing_ms={:.1} build_index_ms={:.1} build_records_ms={:.1} \
         db_write_ms={:.1} serial_ms={:.1} notify_ms={notify_ms:.1} total_ms={:.1}",
        created_records.len(),
        timings.load_zone_ms,
        timings.load_existing_ms,
        timings.build_index_ms,
        timings.build_records_ms,
        timings.db_write_ms,
        timings.serial_ms,
        time::elapsed_ms(total_started)
    );

    let records: Vec<_> = created_records
        .into_iter()
        .map(|(record, actions)| RecordResponse::from_record(&record, &zone_name, actions))
        .collect();

    Ok(CreateBulkRecordsResponse {
        applied: !request.dry_run,
        dry_run: request.dry_run,
        added: if request.dry_run {
            0
        } else {
            records.len() as u64
        },
        records,
        diff,
    })
}
