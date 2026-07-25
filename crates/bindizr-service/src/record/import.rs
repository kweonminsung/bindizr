use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

use chrono::Utc;

use super::{
    RecordService,
    bulk::{PreparedRecord, delete_records_tx, insert_validated_records_tx, load_zone_tx},
    record_value::record_values_equal,
    validation::{
        normalize_record_owner_name, validate_delete_constraints,
        validate_record_add_constraints_normalized,
    },
    zonefile::parse_zone_file,
};
use crate::{
    error::ServiceError,
    log_debug, log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{ImportMode, ImportSummary, ImportZoneFileRequest, ImportZoneFileResponse, RecordDiff},
    zone::{
        history::{ReconstructedRecord, build_record_diff},
        snapshot::save_zone_snapshot_tx,
    },
};

/// A record the import wants present, with its owner name already normalized so
/// it can be compared against existing records.
struct DesiredRecord {
    prepared: PreparedRecord,
    stored_name: String,
}

/// Whether `existing` is the record described by (name, type, value, priority).
fn record_matches(
    existing: &Record,
    stored_name: &str,
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
) -> bool {
    existing.name.eq_ignore_ascii_case(stored_name)
        && existing.record_type == *record_type
        && record_values_equal(
            &existing.value,
            existing.priority,
            value,
            priority,
            record_type,
        )
}

fn desired_matches(existing: &Record, desired: &DesiredRecord) -> bool {
    record_matches(
        existing,
        &desired.stored_name,
        &desired.prepared.record_type,
        &desired.prepared.value,
        desired.prepared.priority,
    )
}

/// Records referenced by the zone's own SOA/primary NS must never be removed.
fn is_protected(zone: &Zone, record: &Record) -> bool {
    validate_delete_constraints(zone, std::slice::from_ref(record)).is_err()
}

/// Outcome of the transactional part of a zone-file import.
struct AppliedImport {
    response: ImportZoneFileResponse,
    zone_name: String,
    changed: bool,
}

impl RecordService {
    /// Import a BIND zone file into an existing zone, reconciling it by mode. On
    /// apply the zone serial is incremented once and a single NOTIFY is sent. If
    /// any record fails validation nothing is applied and the errors are returned.
    pub async fn import_zone_file(
        zone_name: &str,
        request: &ImportZoneFileRequest,
    ) -> Result<ImportZoneFileResponse, ServiceError> {
        let mode = request.mode;
        let dry_run = request.dry_run;

        let t_total = Instant::now();

        // Per-stage timings, filled inside the transaction and emitted as a single
        // debug summary after commit + NOTIFY (see log_debug! below). db_write/serial
        // stay zero when the import is a dry run or a no-op.
        let mut load_zone_ms = 0.0f64;
        let mut load_existing_ms = 0.0f64;
        let mut parse_ms = 0.0f64;
        let mut normalize_ms = 0.0f64;
        let mut build_index_ms = 0.0f64;
        let mut reconcile_ms = 0.0f64;
        let mut validate_ms = 0.0f64;
        let mut db_write_ms = 0.0f64;
        let mut serial_ms = 0.0f64;

        let mut tx = RepositoryService::begin_tx("Failed to import zone file").await?;

        let apply_result: Result<AppliedImport, ServiceError> = async {
            let t = Instant::now();
            let zone = load_zone_tx(&mut tx, zone_name).await?;
            load_zone_ms = t.elapsed().as_secs_f64() * 1000.0;

            let t = Instant::now();
            let parsed = parse_zone_file(&request.content, &zone.name, zone.ttl);
            parse_ms = t.elapsed().as_secs_f64() * 1000.0;
            let mut errors = parsed.errors;
            let mut skipped = 0usize;

            // Normalize parsed records and drop duplicates within the file,
            // indexed by owner name so the dedup check scans only same-name entries.
            let t = Instant::now();
            let mut desired: Vec<DesiredRecord> = Vec::with_capacity(parsed.records.len());
            let mut desired_by_name: HashMap<String, Vec<usize>> =
                HashMap::with_capacity(parsed.records.len());
            for record in parsed.records {
                // Encode the parsed value to its stored form per record type.
                let value = match record.value.to_storage_value(&record.record_type) {
                    Ok(value) => value,
                    Err(e) => {
                        errors.push(format!("{}: {}", record.owner_fqdn, e));
                        continue;
                    }
                };
                let stored_name = match normalize_record_owner_name(&record.owner_fqdn, &zone.name)
                {
                    Ok(normalized) => normalized.stored_name,
                    // Collect any client-input error (4xx) per record; only
                    // internal failures abort the whole import.
                    Err(e) if e.code.http_status() < 500 => {
                        errors.push(format!("{}: {}", record.owner_fqdn, e.message));
                        continue;
                    }
                    Err(e) => return Err(e),
                };

                let name_key = stored_name.to_ascii_lowercase();
                let duplicate_in_file = desired_by_name.get(&name_key).is_some_and(|idxs| {
                    idxs.iter().any(|&i| {
                        desired[i].prepared.record_type == record.record_type
                            && record_values_equal(
                                &desired[i].prepared.value,
                                desired[i].prepared.priority,
                                &value,
                                record.priority,
                                &record.record_type,
                            )
                    })
                });
                if duplicate_in_file {
                    skipped += 1;
                    continue;
                }

                desired_by_name
                    .entry(name_key)
                    .or_default()
                    .push(desired.len());
                desired.push(DesiredRecord {
                    prepared: PreparedRecord {
                        owner_name: record.owner_fqdn,
                        record_type: record.record_type,
                        value,
                        ttl: record.ttl,
                        priority: record.priority,
                    },
                    stored_name,
                });
            }

            normalize_ms = t.elapsed().as_secs_f64() * 1000.0;
            let parsed_count = desired.len();

            // Append never deletes, so only rows sharing an owner name with the
            // file can matter; load just those. Replace and upsert must see
            // every row to compute their implied deletions.
            let t = Instant::now();
            let existing_records = match mode {
                ImportMode::Append => {
                    let mut names: Vec<String> = desired
                        .iter()
                        .map(|d| d.stored_name.to_ascii_lowercase())
                        .collect();
                    names.sort();
                    names.dedup();
                    RepositoryService::get_records_by_zone_id_and_names_tx(&mut tx, zone.id, &names)
                        .await
                }
                ImportMode::Replace | ImportMode::Upsert => {
                    RepositoryService::get_records_by_zone_id_tx(&mut tx, zone.id).await
                }
            }
            .map_err(|e| {
                log_error!("Failed to load zone records: {}", e);
                ServiceError::internal("Failed to import zone file".to_string())
            })?;
            load_existing_ms = t.elapsed().as_secs_f64() * 1000.0;

            // Lowercase each existing owner name once and reuse it across the
            // passes below instead of recomputing it per pass.
            let t = Instant::now();
            let existing_lower: Vec<String> = existing_records
                .iter()
                .map(|e| e.name.to_ascii_lowercase())
                .collect();

            // Index existing records by owner name so each existing/desired
            // record is reconciled against only same-name rows.
            let mut existing_by_name: HashMap<String, Vec<&Record>> =
                HashMap::with_capacity(existing_records.len());
            for (i, record) in existing_records.iter().enumerate() {
                existing_by_name
                    .entry(existing_lower[i].clone())
                    .or_default()
                    .push(record);
            }
            build_index_ms = t.elapsed().as_secs_f64() * 1000.0;

            let t = Instant::now();
            let desired_matches_existing = |e: &Record, e_lower: &str| {
                desired_by_name
                    .get(e_lower)
                    .is_some_and(|idxs| idxs.iter().any(|&i| desired_matches(e, &desired[i])))
            };
            let desired_key_matches_existing = |e: &Record, e_lower: &str| {
                desired_by_name.get(e_lower).is_some_and(|idxs| {
                    idxs.iter()
                        .any(|&i| desired[i].prepared.record_type == e.record_type)
                })
            };

            // Deletions implied by the mode.
            let dels: Vec<Record> = match mode {
                ImportMode::Append => Vec::new(),
                ImportMode::Replace => existing_records
                    .iter()
                    .enumerate()
                    .filter(|(i, e)| {
                        !is_protected(&zone, e) && !desired_matches_existing(e, &existing_lower[*i])
                    })
                    .map(|(_, e)| e.clone())
                    .collect(),
                ImportMode::Upsert => existing_records
                    .iter()
                    .enumerate()
                    .filter(|(i, e)| {
                        desired_key_matches_existing(e, &existing_lower[*i])
                            && !is_protected(&zone, e)
                            && !desired_matches_existing(e, &existing_lower[*i])
                    })
                    .map(|(_, e)| e.clone())
                    .collect(),
            };

            // A present record is left in place unless upsert/replace reconciles
            // its TTL: a change becomes DEL + re-ADD via the batched paths below.
            // TTLs compare by effective value so a stored `None` isn't a change
            // against a file TTL equal to the zone default.
            let reconcile_ttl = matches!(mode, ImportMode::Upsert | ImportMode::Replace);
            let default_ttl = zone.ttl;
            let effective_ttl = |ttl: Option<i32>| ttl.unwrap_or(default_ttl);

            let mut unchanged = 0usize;
            let mut updated = 0usize;
            let mut ttl_dels: Vec<Record> = Vec::new();
            let mut adds: Vec<&DesiredRecord> = Vec::new();
            for d in &desired {
                let desired_ttl = effective_ttl(d.prepared.ttl);
                let mut present = false;
                let mut stale = false;
                if let Some(es) = existing_by_name.get(&d.stored_name.to_ascii_lowercase()) {
                    for &e in es {
                        if desired_matches(e, d) {
                            present = true;
                            if reconcile_ttl && effective_ttl(e.ttl) != desired_ttl {
                                ttl_dels.push(e.clone());
                                stale = true;
                            }
                        }
                    }
                }

                if !present {
                    adds.push(d);
                } else if stale {
                    updated += 1;
                    adds.push(d);
                } else {
                    unchanged += 1;
                }
            }
            reconcile_ms = t.elapsed().as_secs_f64() * 1000.0;

            // Validate additions against an in-memory copy so constraint
            // violations are caught without writing anything. Simulated records
            // are indexed by name so each check scans only same-name candidates.
            let t = Instant::now();
            let del_ids: HashSet<i32> = dels.iter().chain(&ttl_dels).map(|d| d.id).collect();
            let mut simulated_by_name: HashMap<String, Vec<Record>> =
                HashMap::with_capacity(existing_records.len());
            for (i, e) in existing_records.iter().enumerate() {
                if !del_ids.contains(&e.id) {
                    simulated_by_name
                        .entry(existing_lower[i].clone())
                        .or_default()
                        .push(e.clone());
                }
            }
            for add in &adds {
                let same_name = simulated_by_name
                    .entry(add.stored_name.to_ascii_lowercase())
                    .or_default();
                match validate_record_add_constraints_normalized(
                    same_name,
                    &add.stored_name,
                    &add.prepared.record_type,
                    &add.prepared.value,
                    add.prepared.ttl,
                    add.prepared.priority,
                    None,
                ) {
                    Ok(()) => same_name.push(synthetic_record(
                        &add.stored_name,
                        &add.prepared.record_type,
                        &add.prepared.value,
                        add.prepared.ttl,
                        add.prepared.priority,
                    )),
                    Err(e) if e.code.http_status() < 500 => {
                        errors.push(format!("{}: {}", add.prepared.owner_name, e.message))
                    }
                    Err(e) => return Err(e),
                }
            }
            validate_ms = t.elapsed().as_secs_f64() * 1000.0;

            let summary = ImportSummary {
                parsed: parsed_count,
                // `adds` also carries the re-inserted TTL-reconciled records,
                // which are reported under `updated` instead.
                added: adds.len() - updated,
                deleted: dels.len(),
                updated,
                unchanged,
                skipped,
            };

            // The diff is only shown on a dry-run preview, so keep it off the apply
            // hot path (import benchmarks measure records/sec here). Skip it too when
            // errors block the import, so the preview shows no un-appliable changes.
            let diff = if dry_run && errors.is_empty() {
                import_diff(&zone, &existing_records, &adds, &dels, &ttl_dels)
            } else {
                RecordDiff::default()
            };

            let will_apply = errors.is_empty() && !dry_run;
            let has_changes = !dels.is_empty() || !adds.is_empty() || !ttl_dels.is_empty();

            if will_apply && has_changes {
                let new_serial = generate_serial(Some(zone.serial));

                let t = Instant::now();
                let mut all_dels = dels;
                all_dels.extend(ttl_dels);
                delete_records_tx(&mut tx, zone.id, new_serial, &all_dels).await?;

                let to_insert: Vec<Record> = adds
                    .iter()
                    .map(|add| Record {
                        id: 0,
                        name: add.stored_name.clone(),
                        record_type: add.prepared.record_type.clone(),
                        value: add.prepared.value.clone(),
                        ttl: add.prepared.ttl,
                        priority: add.prepared.priority,
                        zone_id: zone.id,
                        created_at: Utc::now(),
                    })
                    .collect();
                insert_validated_records_tx(&mut tx, zone.id, new_serial, &to_insert).await?;
                db_write_ms = t.elapsed().as_secs_f64() * 1000.0;

                let t = Instant::now();
                RepositoryService::update_zone_serial_tx(&mut tx, zone.id, new_serial)
                    .await
                    .map_err(|e| {
                        log_error!("Failed to update zone serial: {}", e);
                        ServiceError::internal("Failed to update zone serial".to_string())
                    })?;

                save_zone_snapshot_tx(&mut tx, &zone, new_serial).await?;
                serial_ms = t.elapsed().as_secs_f64() * 1000.0;
            }

            let response = ImportZoneFileResponse {
                applied: will_apply,
                dry_run,
                summary,
                diff,
                errors,
            };

            Ok(AppliedImport {
                response,
                zone_name: zone.name,
                changed: will_apply && has_changes,
            })
        }
        .await;

        let AppliedImport {
            response,
            zone_name,
            changed,
        } = RepositoryService::finish_tx(tx, apply_result, "Failed to import zone file").await?;

        log_info!(
            "event=zone_import zone={} mode={:?} applied={} added={} deleted={} updated={} unchanged={} skipped={} errors={}",
            zone_name,
            mode,
            response.applied,
            response.summary.added,
            response.summary.deleted,
            response.summary.updated,
            response.summary.unchanged,
            response.summary.skipped,
            response.errors.len(),
        );

        let t = Instant::now();
        if changed && let Err(e) = crate::notify::send_notify_after_update(Some(&zone_name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }
        let notify_ms = t.elapsed().as_secs_f64() * 1000.0;

        // Per-stage breakdown for profiling; debug-gated so it stays out of
        // normal (info-level) runs. NOTIFY is inline only in sync apply mode.
        log_debug!(
            "event=zone_import_timing zone={} mode={:?} parsed={} applied={} parse_ms={:.1} \
             load_zone_ms={:.1} load_existing_ms={:.1} normalize_ms={:.1} build_index_ms={:.1} \
             reconcile_ms={:.1} validate_ms={:.1} db_write_ms={:.1} serial_ms={:.1} notify_ms={:.1} \
             total_ms={:.1}",
            zone_name,
            mode,
            response.summary.parsed,
            response.applied,
            parse_ms,
            load_zone_ms,
            load_existing_ms,
            normalize_ms,
            build_index_ms,
            reconcile_ms,
            validate_ms,
            db_write_ms,
            serial_ms,
            notify_ms,
            t_total.elapsed().as_secs_f64() * 1000.0,
        );

        Ok(response)
    }
}

/// The reconcile as a record diff: `after` is the existing set minus the
/// deletes plus the adds, so `build_record_diff` classifies each RRset.
fn import_diff(
    zone: &Zone,
    existing: &[Record],
    adds: &[&DesiredRecord],
    dels: &[Record],
    ttl_dels: &[Record],
) -> RecordDiff {
    let deleted_ids: HashSet<i32> = dels.iter().chain(ttl_dels).map(|r| r.id).collect();

    let before: Vec<ReconstructedRecord> = existing
        .iter()
        .cloned()
        .map(ReconstructedRecord::from)
        .collect();
    let mut after: Vec<ReconstructedRecord> = existing
        .iter()
        .filter(|record| !deleted_ids.contains(&record.id))
        .cloned()
        .map(ReconstructedRecord::from)
        .collect();
    after.extend(adds.iter().map(|add| ReconstructedRecord {
        name: add.stored_name.clone(),
        record_type: add.prepared.record_type.clone(),
        value: add.prepared.value.clone(),
        ttl: add.prepared.ttl,
        priority: add.prepared.priority,
    }));

    build_record_diff(zone, &before, &after)
}

/// A placeholder record for in-memory comparison only; the negative id keeps it
/// distinct from persisted rows.
fn synthetic_record(
    stored_name: &str,
    record_type: &RecordType,
    value: &str,
    ttl: Option<i32>,
    priority: Option<i32>,
) -> Record {
    Record {
        id: -1,
        name: stored_name.to_string(),
        record_type: record_type.clone(),
        value: value.to_string(),
        ttl,
        priority,
        zone_id: 0,
        created_at: Utc::now(),
    }
}
