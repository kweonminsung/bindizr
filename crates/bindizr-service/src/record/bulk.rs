use std::{collections::HashMap, time::Instant};

use bindizr_core::dns::name::{OwnerName, ZoneName};
use chrono::Utc;

use super::{
    RecordService,
    validation::{
        normalize_record_owner_name, parse_record_type, validate_record_add_constraints_normalized,
    },
};
use crate::{
    RepositoryTx,
    authorization::{Caller, RecordWrite},
    error::ServiceError,
    log_debug, log_debug_enabled, log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone_change::ZoneChange,
    },
    repository::RepositoryService,
    serial::generate_serial,
    timing::{duration_ms, elapsed_ms},
    types::{BulkRecordsResponse, GetRecordResponse, RecordDiff, RecordItem, RecordValueRequest},
    zone::{
        ZoneService,
        history::{ReconstructedRecord, build_record_diff},
    },
};

/// Per-stage timings, emitted as one debug summary after commit + NOTIFY.
#[derive(Default)]
struct BulkTimings {
    load_zone_ms: f64,
    load_existing_ms: f64,
    build_index_ms: f64,
    normalize_ms: f64,
    validate_ms: f64,
    db_write_ms: f64,
    serial_ms: f64,
}

/// A record whose type and value are parsed and ready to insert. The owner name
/// is kept raw so the constraint validator can normalize it against the zone.
pub(super) struct PreparedRecord {
    pub owner_name: String,
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}

/// Parse the record type and encode the value into its record-row form.
pub(super) fn prepare_record(
    name: &str,
    record_type: &str,
    value: &RecordValueRequest,
    ttl: Option<i32>,
    priority: Option<i32>,
) -> Result<PreparedRecord, ServiceError> {
    let record_type = parse_record_type(record_type)?;
    let value = value
        .to_encoded_value(&record_type, priority)
        .map_err(ServiceError::invalid_record_value)?;

    Ok(PreparedRecord {
        owner_name: name.to_string(),
        record_type,
        value,
        ttl,
        priority,
    })
}

pub(super) fn zone_changes_for(
    zone_id: i32,
    new_serial: i32,
    operation: &str,
    records: &[Record],
) -> Vec<ZoneChange> {
    records
        .iter()
        .map(|record| ZoneChange {
            id: 0,
            zone_id,
            serial: new_serial,
            operation: operation.to_string(),
            record_name: record.name.clone(),
            record_type: record.record_type.to_string(),
            record_value: record.value.clone(),
            record_ttl: record.ttl,
            record_priority: record.priority,
        })
        .collect()
}

impl RecordService {
    /// Insert records with their ADD zone changes for IXFR. The caller has
    /// already validated the rows.
    pub(crate) async fn insert_records_with_changes_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        new_serial: i32,
        records: &[Record],
    ) -> Result<Vec<Record>, ServiceError> {
        if records.is_empty() {
            return Ok(Vec::new());
        }

        let created_records = RepositoryService::create_records_tx(tx, records).await?;
        let changes = zone_changes_for(zone_id, new_serial, ZoneChange::OP_ADD, &created_records);
        RepositoryService::create_zone_changes_tx(tx, &changes).await?;
        Ok(created_records)
    }

    /// Delete records with their DEL zone changes for IXFR.
    pub(crate) async fn delete_records_with_changes_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        new_serial: i32,
        records: &[Record],
    ) -> Result<(), ServiceError> {
        if records.is_empty() {
            return Ok(());
        }

        let ids: Vec<i32> = records.iter().map(|r| r.id).collect();
        RepositoryService::delete_records_tx(tx, &ids).await?;
        let changes = zone_changes_for(zone_id, new_serial, ZoneChange::OP_DEL, records);
        RepositoryService::create_zone_changes_tx(tx, &changes).await?;
        Ok(())
    }
}

impl RecordService {
    /// Insert many records into a zone in one transaction. The zone serial is
    /// incremented once, a single snapshot is saved, and a single NOTIFY is sent
    /// after commit. Either every record is inserted or none is. On `dry_run`
    /// the same validation runs but nothing is written and no NOTIFY is sent;
    /// the returned records are the validated would-be records (placeholder
    /// IDs). `caller` is authorized inside the bulk transaction, so its grants
    /// are decided against the zone this tx locked.
    pub async fn create_bulk(
        caller: &Caller,
        zone_name: &str,
        items: &[RecordItem],
        dry_run: bool,
    ) -> Result<BulkRecordsResponse, ServiceError> {
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
                prepare_record(
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

        let mut tx = RepositoryService::begin_tx("Failed to create records").await?;

        let apply_result = async {
            let t = Instant::now();
            let zone = ZoneService::get_by_name_tx(&mut tx, zone_name).await?;
            timings.load_zone_ms = elapsed_ms(t);

            // Authorized before any row is read, so a caller without a grant gets
            // 403 instead of a constraint error naming records in the zone. Dry
            // runs authorize too, so a preview never claims a batch the caller
            // could not apply. Normalization errors are ignored here; the
            // validation loop below reports them authoritatively.
            let writes: Vec<RecordWrite<'_>> = prepared
                .iter()
                .filter_map(|p| {
                    normalize_record_owner_name(&p.owner_name, &zone.name)
                        .ok()
                        .map(|name| RecordWrite {
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
            let mut batch_names: Vec<String> =
                writes.iter().map(|w| w.relative_name.to_stored()).collect();
            batch_names.sort();
            batch_names.dedup();

            let existing_records = match RepositoryService::get_records_by_zone_id_and_names_tx(
                &mut tx,
                zone.id,
                &batch_names,
            )
            .await
            {
                Ok(records) => records,
                Err(e) => {
                    log_error!("Failed to load zone records: {}", e);
                    return Err(ServiceError::internal(
                        "Failed to create records".to_string(),
                    ));
                }
            };
            timings.load_existing_ms = elapsed_ms(t);

            let new_serial = generate_serial(Some(zone.serial))?;

            // The diff is only shown on a dry-run preview, so keep the `before`
            // snapshot (and pay for building the diff) off the apply hot path.
            let before_records = if dry_run {
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

            // Time normalization and validation separately so validate_ms stays
            // comparable with zone import, which normalizes in an earlier pass;
            // debug-gated to keep the clock reads off the hot path.
            let timing_enabled = log_debug_enabled!();
            let mut normalize_dur = std::time::Duration::ZERO;
            let mut validate_dur = std::time::Duration::ZERO;
            let mut to_insert = Vec::with_capacity(prepared.len());
            for prepared_record in &prepared {
                let t = timing_enabled.then(Instant::now);
                let owner_name =
                    normalize_record_owner_name(&prepared_record.owner_name, &zone.name)?;
                if let Some(t) = t {
                    normalize_dur += t.elapsed();
                }

                let same_name = records_by_name.entry(owner_name.clone()).or_default();

                // Fixed at write time: a later zone TTL change will not move it.
                let ttl = prepared_record.ttl.unwrap_or(zone.ttl);

                let t = timing_enabled.then(Instant::now);
                validate_record_add_constraints_normalized(
                    same_name,
                    &owner_name,
                    &prepared_record.record_type,
                    &prepared_record.value,
                    ttl,
                    prepared_record.priority,
                    None,
                )?;
                if let Some(t) = t {
                    validate_dur += t.elapsed();
                }

                let record = Record {
                    id: 0,
                    name: owner_name.clone(),
                    record_type: prepared_record.record_type.clone(),
                    value: prepared_record.value.clone(),
                    ttl,
                    priority: prepared_record.priority,
                    zone_id: zone.id,
                    created_at: Utc::now(),
                };
                same_name.push(record.clone());
                to_insert.push(record);
            }
            timings.normalize_ms = duration_ms(normalize_dur);
            timings.validate_ms = duration_ms(validate_dur);

            if dry_run {
                // `after` = existing plus the inserts, so an insert into an
                // existing RRset reads as `changed`, not a bare `added`.
                let before: Vec<ReconstructedRecord> = before_records
                    .into_iter()
                    .map(ReconstructedRecord::from)
                    .collect();
                let mut after = before.clone();
                after.extend(to_insert.iter().cloned().map(ReconstructedRecord::from));
                let diff = build_record_diff(&zone, &before, &after);
                return Ok((to_insert, zone.name, diff));
            }

            let t = Instant::now();
            let created_records = RecordService::insert_records_with_changes_tx(
                &mut tx, zone.id, new_serial, &to_insert,
            )
            .await?;
            timings.db_write_ms = elapsed_ms(t);

            // Advance the serial once so IXFR consumers detect the batch
            let t = Instant::now();
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;
            timings.serial_ms = elapsed_ms(t);

            Ok::<(Vec<Record>, ZoneName, RecordDiff), ServiceError>((
                created_records,
                zone.name,
                RecordDiff::default(),
            ))
        }
        .await;

        let (created_records, zone_name, diff) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create records").await?;

        log_info!(
            "event=record_bulk_create zone={} count={} dry_run={}",
            zone_name,
            created_records.len(),
            dry_run
        );

        let t = Instant::now();
        if !dry_run
            && let Err(e) = crate::notify::send_notify_after_update(Some(zone_name.as_str())).await
        {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }
        let notify_ms = elapsed_ms(t);

        // Per-stage breakdown for profiling; debug-gated so it stays out of
        // normal (info-level) runs. NOTIFY is inline only in sync apply mode.
        log_debug!(
            "event=record_bulk_create_timing zone={} count={} prepare_ms={:.1} load_zone_ms={:.1} \
             load_existing_ms={:.1} build_index_ms={:.1} normalize_ms={:.1} validate_ms={:.1} \
             db_write_ms={:.1} serial_ms={:.1} notify_ms={:.1} total_ms={:.1}",
            zone_name,
            created_records.len(),
            prepare_ms,
            timings.load_zone_ms,
            timings.load_existing_ms,
            timings.build_index_ms,
            timings.normalize_ms,
            timings.validate_ms,
            timings.db_write_ms,
            timings.serial_ms,
            notify_ms,
            elapsed_ms(t_total),
        );

        let records = created_records
            .iter()
            .map(|record| GetRecordResponse::from_record_and_zone_name(record, &zone_name))
            .collect();
        Ok(BulkRecordsResponse {
            applied: !dry_run,
            dry_run,
            inserted: if dry_run { 0 } else { created_records.len() },
            records,
            diff,
        })
    }
}
