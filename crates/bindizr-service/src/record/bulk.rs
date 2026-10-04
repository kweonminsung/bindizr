use std::{collections::HashMap, time::Instant};

use bindizr_core::{
    dns::{
        Serial, Ttl,
        name::{OwnerName, ZoneName},
    },
    model::{record::RecordId, role_grant::Action, zone::ZoneId},
};
use bindizr_db::LockLevel;
use chrono::Utc;

use super::validation::{
    normalize_record_owner_name, parse_record_type, validate_record_add_constraints_normalized,
};
use crate::{
    Context, Transaction,
    authorization::{Caller, RecordWrite},
    dnssec,
    error::ServiceError,
    model::{
        record::{Record, RecordData, RecordType},
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    serial::generate_serial,
    time::elapsed_ms,
    transaction,
    ttl::validate_record_ttl,
    types::{
        BulkRecordsResponse, CreateBulkRecordsRequest, GetRecordResponse, RecordDiff, RecordValue,
        Run,
    },
    zone::{self, diff::build_record_diff},
};

/// Per-stage timings, emitted as one debug summary after commit + NOTIFY.
#[derive(Default, Debug, Clone, PartialEq)]
struct BulkTimings {
    load_zone_ms: f64,
    load_existing_ms: f64,
    build_index_ms: f64,
    build_records_ms: f64,
    db_write_ms: f64,
    serial_ms: f64,
}

/// A record whose type and value are parsed and ready to insert. The owner name
/// is kept raw so the constraint validator can normalize it against the zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedRecord {
    pub(crate) raw_name: String,
    pub(crate) record_type: RecordType,
    pub(crate) value: String,
    pub(crate) ttl: Option<Ttl>,
    pub(crate) priority: Option<i32>,
}

/// Parse the record type and encode the value into its record-row form.
pub(crate) fn parse_record_request(
    name: &str,
    record_type: &str,
    value: &RecordValue,
    ttl: Option<i32>,
    priority: Option<i32>,
) -> Result<PreparedRecord, ServiceError> {
    let record_type = parse_record_type(record_type)?;
    let ttl = ttl.map(validate_record_ttl).transpose()?;
    let priority = record_type.stored_priority(priority);
    let value = value
        .to_encoded_value(&record_type, priority)
        .map_err(ServiceError::invalid_record_value)?;

    Ok(PreparedRecord {
        raw_name: name.to_string(),
        record_type,
        value,
        ttl,
        priority,
    })
}

/// Insert records with their ADD zone changes for IXFR. The caller has
/// already validated the rows.
pub(crate) async fn create_with_changes_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    new_serial: Serial,
    records: &[Record],
) -> Result<Vec<Record>, ServiceError> {
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let created_records = bindizr_db::record::create_many_tx(tx, records).await?;
    let changes: Vec<ZoneChange> = created_records
        .iter()
        .map(|record| ZoneChange {
            zone_id,
            serial: new_serial,
            operation: ChangeOperation::Add,
            record_name: record.name.clone(),
            record_type: JournalRecordType::User(record.record_type),
            record_value: Some(record.value.clone()),
            record_rdata: None,
            record_ttl: record.ttl,
            record_priority: record.priority,
            derived: false,
        })
        .collect();
    bindizr_db::zone_change::create_many_tx(tx, &changes).await?;
    Ok(created_records)
}

/// Update one record with its DEL(old)+ADD(new) zone changes for IXFR. The
/// caller has already validated the row.
pub(crate) async fn update_with_changes_tx(
    tx: &mut Transaction<'_>,
    new_serial: Serial,
    existing: &Record,
    updated: Record,
) -> Result<Record, ServiceError> {
    let updated = bindizr_db::record::update_tx(tx, updated).await?;
    let change = |operation, record: &Record| ZoneChange {
        zone_id: record.zone_id,
        serial: new_serial,
        operation,
        record_name: record.name.clone(),
        record_type: JournalRecordType::User(record.record_type),
        record_value: Some(record.value.clone()),
        record_rdata: None,
        record_ttl: record.ttl,
        record_priority: record.priority,
        derived: false,
    };
    let changes = [
        change(ChangeOperation::Delete, existing),
        change(ChangeOperation::Add, &updated),
    ];
    bindizr_db::zone_change::create_many_tx(tx, &changes).await?;
    Ok(updated)
}

/// Delete records with their DEL zone changes for IXFR.
pub(crate) async fn delete_with_changes_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    new_serial: Serial,
    records: &[Record],
) -> Result<(), ServiceError> {
    if records.is_empty() {
        return Ok(());
    }

    let ids: Vec<RecordId> = records.iter().map(|r| r.id).collect();
    bindizr_db::record::delete_many_tx(tx, &ids).await?;
    let changes: Vec<ZoneChange> = records
        .iter()
        .map(|record| ZoneChange {
            zone_id,
            serial: new_serial,
            operation: ChangeOperation::Delete,
            record_name: record.name.clone(),
            record_type: JournalRecordType::User(record.record_type),
            record_value: Some(record.value.clone()),
            record_rdata: None,
            record_ttl: record.ttl,
            record_priority: record.priority,
            derived: false,
        })
        .collect();
    bindizr_db::zone_change::create_many_tx(tx, &changes).await?;
    Ok(())
}
/// Insert records atomically after locking and authorizing the zone, with one serial,
/// version, and post-commit NOTIFY; a dry run validates and returns the proposed rows.
pub async fn create_bulk(
    cx: &Context,
    caller: &Caller,
    request: &CreateBulkRecordsRequest,
) -> Result<BulkRecordsResponse, ServiceError> {
    let zone_name = &zone::normalize_name(&request.zone_name)?;
    let items = &request.records;
    let run = Run::from_dry_run(request.dry_run);
    if items.is_empty() {
        return Err(ServiceError::invalid_input(
            "no records provided for bulk insert".to_string(),
        ));
    }

    let t_total = Instant::now();

    // Validate types and values up front so a malformed item fails fast.
    let t = Instant::now();
    let prepared = items
        .iter()
        .map(|item| {
            parse_record_request(
                &item.name,
                &item.record_type,
                &item.value,
                item.ttl,
                item.priority,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let prepare_ms = elapsed_ms(t);

    let mut timings = BulkTimings::default();

    let mut tx = transaction::begin_tx(cx, "failed to create records").await?;

    let apply_result = async {
        let t = Instant::now();
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        timings.load_zone_ms = elapsed_ms(t);

        // Authorize before loading existing record rows so an ungranted caller
        // gets 404 instead of constraint details; dry runs included.
        // A name that will not parse lists no write; validation reports it.
        let writes: Vec<RecordWrite<'_>> = prepared
            .iter()
            .filter_map(|p| {
                normalize_record_owner_name(&p.raw_name, &zone.name)
                    .ok()
                    .map(|name| RecordWrite {
                        action: Action::RecordCreate,
                        relative_name: name,
                        record_type: Some(&p.record_type),
                    })
            })
            .collect();
        caller
            .authorize_record_writes_tx(&mut tx, &zone, &writes)
            .await?;

        // Only records whose owner name appears in the batch can conflict, so
        // load just those instead of the whole zone.
        let t = Instant::now();
        let mut batch_names: Vec<OwnerName> =
            writes.iter().map(|w| w.relative_name.clone()).collect();
        batch_names.sort();
        batch_names.dedup();

        let existing_records = match bindizr_db::record::list_by_names_tx(
            &mut tx,
            zone.id,
            &batch_names,
            LockLevel::Exclusive,
        )
        .await
        {
            Ok(records) => records,
            Err(e) => {
                log::error!("Failed to load zone records: {}", e);
                return Err(ServiceError::internal_with_source(
                    "failed to create records",
                    e,
                ));
            }
        };
        timings.load_existing_ms = elapsed_ms(t);

        let new_serial = generate_serial(Some(zone.serial))?;

        // The diff is only shown on a dry-run preview, so keep the `before`
        // copy (and pay for building the diff) off the apply hot path.
        let before_records = if run.is_dry_run() {
            existing_records.clone()
        } else {
            Vec::new()
        };

        // Index existing records by owner name so constraint checks scan
        // only same-name records; new records join the index as we go so
        // intra-batch conflicts are still detected.
        let t = Instant::now();
        let mut records_by_name: HashMap<OwnerName, Vec<Record>> =
            HashMap::with_capacity(existing_records.len());
        for record in existing_records {
            records_by_name
                .entry(record.name.clone())
                .or_default()
                .push(record);
        }
        timings.build_index_ms = elapsed_ms(t);

        let t = Instant::now();
        let mut to_insert = Vec::with_capacity(prepared.len());
        for prepared_record in &prepared {
            let owner_name = normalize_record_owner_name(&prepared_record.raw_name, &zone.name)?;

            let records_at_name = records_by_name.entry(owner_name.clone()).or_default();

            // Fixed at write time: a later zone TTL change will not move it.
            let ttl = prepared_record.ttl.unwrap_or(zone.default_ttl);

            validate_record_add_constraints_normalized(
                records_at_name,
                &owner_name,
                &prepared_record.record_type,
                &prepared_record.value,
                ttl,
                prepared_record.priority,
                None,
            )?;

            let record = Record {
                id: RecordId::UNWRITTEN,
                name: owner_name,
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
        timings.build_records_ms = elapsed_ms(t);

        if run.is_dry_run() {
            // Mirror `validate_delegations_tx` against the simulated final
            // state: an insert-only batch can only violate it at names it
            // touches, and those are all indexed here.
            for (name, rows) in &records_by_name {
                if rows.iter().any(|r| r.record_type == RecordType::Ds)
                    && !rows.iter().any(|r| r.record_type == RecordType::Ns)
                {
                    return Err(ServiceError::record_conflict(format!(
                        "DS records at '{}' require delegation NS records at the same name",
                        name
                    )));
                }
            }

            // `after` = existing plus the inserts, so an insert into an
            // existing record set reads as `changed`, not a bare `added`.
            let before =
                caller.readable_records(zone.id, before_records.into_iter().map(RecordData::from));
            let mut after = before.clone();
            for record in &to_insert {
                after.push_written(RecordData::from(record.clone()));
            }
            let diff = build_record_diff(&zone, &before, &after);
            return Ok((to_insert, zone.name, diff));
        }

        let t = Instant::now();
        let created_records =
            super::create_with_changes_tx(&mut tx, zone.id, new_serial, &to_insert).await?;
        timings.db_write_ms = elapsed_ms(t);

        let t = Instant::now();
        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
        // Advance the serial once so IXFR consumers detect the batch.
        zone::advance_serial_tx(&mut tx, cx, &zone, new_serial, caller.change_attribution())
            .await?;
        timings.serial_ms = elapsed_ms(t);

        Ok::<(Vec<Record>, ZoneName, RecordDiff), ServiceError>((
            created_records,
            zone.name,
            RecordDiff::default(),
        ))
    }
    .await;

    let (created_records, zone_name, diff) =
        transaction::finish_tx(tx, apply_result, "failed to create records").await?;

    log::info!(
        "event=record_bulk_create zone={} count={} dry_run={}",
        zone_name,
        created_records.len(),
        run.is_dry_run()
    );

    let t = Instant::now();
    if !run.is_dry_run() {
        crate::notify::notify_after_update(cx, &zone_name).await;
    }
    let notify_ms = elapsed_ms(t);

    // Per-stage breakdown for profiling; debug-gated so it stays out of
    // normal (info-level) runs. NOTIFY is inline only in sync apply mode.
    log::debug!(
        "event=record_bulk_create_timing zone={} count={} prepare_ms={:.1} load_zone_ms={:.1} \
         load_existing_ms={:.1} build_index_ms={:.1} build_records_ms={:.1} \
         db_write_ms={:.1} serial_ms={:.1} notify_ms={:.1} total_ms={:.1}",
        zone_name,
        created_records.len(),
        prepare_ms,
        timings.load_zone_ms,
        timings.load_existing_ms,
        timings.build_index_ms,
        timings.build_records_ms,
        timings.db_write_ms,
        timings.serial_ms,
        notify_ms,
        elapsed_ms(t_total),
    );

    let records = created_records
        .iter()
        .map(|record| {
            GetRecordResponse::from_record(
                record,
                &zone_name,
                caller.record_actions(record.zone_id, &record.name, &record.record_type),
            )
        })
        .collect();
    Ok(BulkRecordsResponse {
        applied: !run.is_dry_run(),
        dry_run: run.is_dry_run(),
        added: if run.is_dry_run() {
            0
        } else {
            created_records.len() as u64
        },
        records,
        diff,
    })
}
