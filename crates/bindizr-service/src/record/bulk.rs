use std::collections::HashMap;
use std::time::Instant;

use chrono::Utc;

use super::{
    RecordService,
    validation::{normalize_record_owner_name, validate_record_add_constraints_normalized},
};
use crate::{
    RepositoryTx,
    error::ServiceError,
    log_debug, log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType, RecordWithZone},
        zone::Zone,
        zone_change::ZoneChange,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{BulkRecordItem, RecordValueRequest},
    zone::{snapshot::save_zone_snapshot_tx, validation::normalize_zone_name},
};

/// A record whose type and value are parsed and ready to insert. The owner name
/// is kept raw so the constraint validator can normalize it against the zone.
pub(super) struct PreparedRecord {
    pub owner_name: String,
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}

/// Parse the record type and encode the value into storage form.
pub(super) fn prepare_record(
    name: &str,
    record_type: &str,
    value: &RecordValueRequest,
    ttl: Option<i32>,
    priority: Option<i32>,
) -> Result<PreparedRecord, ServiceError> {
    let record_type = record_type
        .parse::<RecordType>()
        .map_err(|_| ServiceError::BadRequest(format!("Invalid record type: {}", record_type)))?;
    let value = value
        .to_storage_value(&record_type)
        .map_err(ServiceError::BadRequest)?;

    Ok(PreparedRecord {
        owner_name: name.to_string(),
        record_type,
        value,
        ttl,
        priority,
    })
}

fn zone_changes_for(
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

/// Insert records that the caller has already validated, with their ADD zone changes.
pub(super) async fn insert_validated_records_tx(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
    new_serial: i32,
    records: &[Record],
) -> Result<Vec<Record>, ServiceError> {
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let created_records = RepositoryService::create_records_tx(tx, records).await?;
    let changes = zone_changes_for(zone_id, new_serial, "ADD", &created_records);
    RepositoryService::create_zone_changes_tx(tx, &changes).await?;
    Ok(created_records)
}

/// Delete records, with their DEL zone changes.
pub(super) async fn delete_records_tx(
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
    let changes = zone_changes_for(zone_id, new_serial, "DEL", records);
    RepositoryService::create_zone_changes_tx(tx, &changes).await?;
    Ok(())
}

/// Load the target zone inside the transaction, returning `NotFound` if missing.
pub(super) async fn load_zone_tx(
    tx: &mut RepositoryTx<'_>,
    zone_name: &str,
) -> Result<Zone, ServiceError> {
    let lookup_zone_name = normalize_zone_name(zone_name)?;
    match RepositoryService::get_zone_by_name_tx(tx, &lookup_zone_name).await {
        Ok(Some(zone)) => Ok(zone),
        Ok(None) => Err(ServiceError::NotFound(format!(
            "Zone with name '{}' not found",
            zone_name
        ))),
        Err(e) => {
            log_error!("Failed to fetch zone: {}", e);
            Err(ServiceError::Internal("Failed to fetch zone".to_string()))
        }
    }
}

impl RecordService {
    /// Insert many records into a zone in one transaction. The zone serial is
    /// incremented once, a single snapshot is saved, and a single NOTIFY is sent
    /// after commit. Either every record is inserted or none is.
    pub async fn create_bulk(
        zone_name: &str,
        items: &[BulkRecordItem],
    ) -> Result<Vec<RecordWithZone>, ServiceError> {
        if items.is_empty() {
            return Err(ServiceError::BadRequest(
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
        let prepare_ms = t.elapsed().as_secs_f64() * 1000.0;

        // Per-stage timings, filled inside the transaction and emitted as a single
        // debug summary after commit + NOTIFY (see log_debug! below).
        let mut load_zone_ms = 0.0f64;
        let mut load_existing_ms = 0.0f64;
        let mut build_index_ms = 0.0f64;
        let mut normalize_ms = 0.0f64;
        let mut validate_ms = 0.0f64;
        let mut db_write_ms = 0.0f64;
        let mut serial_ms = 0.0f64;

        let mut tx = RepositoryService::begin_tx("Failed to create records").await?;

        let apply_result = async {
            let t = Instant::now();
            let zone = load_zone_tx(&mut tx, zone_name).await?;
            load_zone_ms = t.elapsed().as_secs_f64() * 1000.0;

            // Only records whose owner name appears in the batch can conflict, so
            // load just those instead of the whole zone. Normalization errors are
            // ignored here; the validation loop below reports them authoritatively.
            let t = Instant::now();
            let mut batch_names: Vec<String> = prepared
                .iter()
                .filter_map(|p| normalize_record_owner_name(&p.owner_name, &zone.name).ok())
                .map(|n| n.stored_name.to_ascii_lowercase())
                .collect();
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
                    return Err(ServiceError::Internal(
                        "Failed to create records".to_string(),
                    ));
                }
            };
            load_existing_ms = t.elapsed().as_secs_f64() * 1000.0;

            let new_serial = generate_serial(Some(zone.serial));

            // Index existing records by owner name so each record's constraint
            // check scans only same-name records instead of the whole zone (an
            // O(batch x zone) scan otherwise). Newly added records join the index
            // as we go, so intra-batch conflicts are still detected.
            let t = Instant::now();
            let mut records_by_name: HashMap<String, Vec<Record>> = HashMap::new();
            for record in existing_records {
                records_by_name
                    .entry(record.name.to_ascii_lowercase())
                    .or_default()
                    .push(record);
            }
            build_index_ms = t.elapsed().as_secs_f64() * 1000.0;

            // Time normalization and constraint validation separately: bulk does
            // both per record here, so lumping them would inflate validate_ms
            // versus zone import, which normalizes in an earlier pass.
            let mut normalize_dur = std::time::Duration::ZERO;
            let mut validate_dur = std::time::Duration::ZERO;
            let mut to_insert = Vec::with_capacity(prepared.len());
            for prepared_record in &prepared {
                let t = Instant::now();
                let normalized_owner =
                    normalize_record_owner_name(&prepared_record.owner_name, &zone.name)?;
                normalize_dur += t.elapsed();

                let same_name = records_by_name
                    .entry(normalized_owner.stored_name.to_ascii_lowercase())
                    .or_default();

                let t = Instant::now();
                validate_record_add_constraints_normalized(
                    same_name,
                    &prepared_record.owner_name,
                    &normalized_owner.stored_name,
                    &prepared_record.record_type,
                    &prepared_record.value,
                    prepared_record.priority,
                    None,
                )?;
                validate_dur += t.elapsed();

                let record = Record {
                    id: 0,
                    name: normalized_owner.stored_name,
                    record_type: prepared_record.record_type.clone(),
                    value: prepared_record.value.clone(),
                    ttl: prepared_record.ttl,
                    priority: prepared_record.priority,
                    zone_id: zone.id,
                    created_at: Utc::now(),
                };
                same_name.push(record.clone());
                to_insert.push(record);
            }
            normalize_ms = normalize_dur.as_secs_f64() * 1000.0;
            validate_ms = validate_dur.as_secs_f64() * 1000.0;

            let t = Instant::now();
            let created_records =
                insert_validated_records_tx(&mut tx, zone.id, new_serial, &to_insert).await?;
            db_write_ms = t.elapsed().as_secs_f64() * 1000.0;

            // Increment zone serial once so IXFR consumers detect the batch
            let t = Instant::now();
            RepositoryService::update_zone_serial_tx(&mut tx, zone.id, new_serial)
                .await
                .map_err(|e| {
                    log_error!("Failed to update zone serial: {}", e);
                    ServiceError::Internal("Failed to update zone serial".to_string())
                })?;

            save_zone_snapshot_tx(&mut tx, &zone, new_serial).await?;
            serial_ms = t.elapsed().as_secs_f64() * 1000.0;

            Ok::<(Vec<Record>, String), ServiceError>((created_records, zone.name))
        }
        .await;

        let (created_records, zone_name) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create records").await?;

        log_info!(
            "event=record_bulk_create zone={} count={}",
            zone_name,
            created_records.len()
        );

        // Send NOTIFY to secondary servers
        let t = Instant::now();
        if let Err(e) = crate::notify::send_notify_after_update(Some(&zone_name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }
        let notify_ms = t.elapsed().as_secs_f64() * 1000.0;

        // Per-stage breakdown for profiling; debug-gated so it stays out of
        // normal (info-level) runs. NOTIFY is inline only in sync apply mode.
        log_debug!(
            "event=record_bulk_create_timing zone={} count={} prepare_ms={:.1} load_zone_ms={:.1} \
             load_existing_ms={:.1} build_index_ms={:.1} normalize_ms={:.1} validate_ms={:.1} \
             db_write_ms={:.1} serial_ms={:.1} notify_ms={:.1} total_ms={:.1}",
            zone_name,
            created_records.len(),
            prepare_ms,
            load_zone_ms,
            load_existing_ms,
            build_index_ms,
            normalize_ms,
            validate_ms,
            db_write_ms,
            serial_ms,
            notify_ms,
            t_total.elapsed().as_secs_f64() * 1000.0,
        );

        Ok(created_records
            .into_iter()
            .map(|record| RecordWithZone::new(record, zone_name.clone()))
            .collect())
    }
}
