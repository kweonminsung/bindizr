use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_db::repository::LockLevel;
use chrono::Utc;

use super::{
    RecordService,
    bulk::PreparedRecord,
    validation::{
        normalize_record_owner_name, validate_delete_constraints,
        validate_record_add_constraints_normalized,
    },
    zonefile::parse_zone_file,
};
use crate::{
    authorization::Caller,
    dnssec::DnssecService,
    error::ServiceError,
    log_debug, log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::RepositoryService,
    serial::generate_serial,
    timing::elapsed_ms,
    types::{ImportMode, ImportSummary, ImportZoneFileRequest, ImportZoneFileResponse, RecordDiff},
    zone::{
        ZoneService,
        history::{ReconstructedRecord, build_record_diff},
    },
};

/// A record the import wants present, with its owner name already normalized so
/// it can be compared against existing records.
struct DesiredRecord {
    prepared: PreparedRecord,
    stored_name: OwnerName,
}

/// Whether `existing` is the record the import wants present.
fn desired_matches(existing: &Record, desired: &DesiredRecord) -> bool {
    let record_type = &desired.prepared.record_type;
    existing.name == desired.stored_name
        && existing.record_type == *record_type
        && record_type.values_equal(
            &existing.value,
            existing.priority,
            &desired.prepared.value,
            desired.prepared.priority,
        )
}

/// Records referenced by the zone's own SOA/mname NS must never be removed.
fn is_protected(zone: &Zone, record: &Record) -> bool {
    validate_delete_constraints(zone, std::slice::from_ref(record)).is_err()
}

/// Outcome of the transactional part of a zone-file import.
struct AppliedImport {
    response: ImportZoneFileResponse,
    zone_name: ZoneName,
    changed: bool,
}

/// Per-stage timings, emitted as one debug summary after commit + NOTIFY;
/// `db_write_ms`/`serial_ms` stay zero on a dry run or no-op.
#[derive(Default)]
struct ImportTimings {
    load_zone_ms: f64,
    load_existing_ms: f64,
    parse_ms: f64,
    normalize_ms: f64,
    build_index_ms: f64,
    reconcile_ms: f64,
    validate_ms: f64,
    db_write_ms: f64,
    serial_ms: f64,
}

impl RecordService {
    /// Import a BIND zone file into an existing zone, reconciling it by mode. On
    /// apply the zone serial is incremented once and a single NOTIFY is sent. If
    /// any record fails validation nothing is applied and the errors are returned.
    pub async fn import_zone_file(
        caller: &Caller,
        zone_name: &str,
        request: &ImportZoneFileRequest,
    ) -> Result<ImportZoneFileResponse, ServiceError> {
        caller.require_global("import zone files")?;

        let mode = request.mode;
        let dry_run = request.dry_run;

        let t_total = Instant::now();

        let mut timings = ImportTimings::default();

        let mut tx = RepositoryService::begin_tx("Failed to import zone file").await?;

        let apply_result: Result<AppliedImport, ServiceError> = async {
            let t = Instant::now();
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            timings.load_zone_ms = elapsed_ms(t);

            let t = Instant::now();
            let parsed = parse_zone_file(&request.content, zone.name.as_str(), zone.default_ttl);
            timings.parse_ms = elapsed_ms(t);
            let mut errors = parsed.errors;
            let mut skipped = 0usize;

            // Normalize parsed records and drop duplicates within the file,
            // indexed by owner name so the dedup check scans only same-name entries.
            let t = Instant::now();
            let mut desired: Vec<DesiredRecord> = Vec::with_capacity(parsed.records.len());
            let mut desired_by_name: HashMap<OwnerName, Vec<usize>> =
                HashMap::with_capacity(parsed.records.len());
            for record in parsed.records {
                let value = match record
                    .value
                    .to_encoded_value(&record.record_type, record.priority)
                {
                    Ok(value) => value,
                    Err(e) => {
                        errors.push(format!("{}: {}", record.owner_fqdn, e));
                        continue;
                    }
                };
                let stored_name = match normalize_record_owner_name(&record.owner_fqdn, &zone.name)
                {
                    Ok(stored_name) => stored_name,
                    // Collect any client-input error (4xx) per record; only
                    // internal failures abort the whole import.
                    Err(e) if e.code.http_status() < 500 => {
                        errors.push(format!("{}: {}", record.owner_fqdn, e.message));
                        continue;
                    }
                    Err(e) => return Err(e),
                };

                let name_key = stored_name.clone();
                let duplicate_in_file = desired_by_name.get(&name_key).and_then(|idxs| {
                    idxs.iter().copied().find(|&i| {
                        desired[i].prepared.record_type == record.record_type
                            && record.record_type.values_equal(
                                &desired[i].prepared.value,
                                desired[i].prepared.priority,
                                &value,
                                record.priority,
                            )
                    })
                });
                if let Some(kept) = duplicate_in_file {
                    let kept_ttl = desired[kept].prepared.ttl.unwrap_or(zone.default_ttl);
                    let this_ttl = record.ttl;
                    // The same RR at two TTLs is a mixed-TTL RRset (RFC 2181,
                    // Section 5.2); deduplication must not swallow the conflict.
                    if kept_ttl != this_ttl {
                        errors.push(format!(
                            "{}: duplicate {} record with conflicting TTLs {} and {}",
                            record.owner_fqdn, record.record_type, kept_ttl, this_ttl
                        ));
                    } else {
                        skipped += 1;
                    }
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
                        ttl: Some(record.ttl),
                        priority: record.priority,
                    },
                    stored_name,
                });
            }

            timings.normalize_ms = elapsed_ms(t);
            let parsed_count = desired.len();

            // Append never deletes, so only rows sharing an owner name with the
            // file can matter; load just those. Replace and upsert must see
            // every row to compute their implied deletions.
            let t = Instant::now();
            let existing_records = match mode {
                ImportMode::Append => {
                    let mut names: Vec<OwnerName> =
                        desired.iter().map(|d| d.stored_name.clone()).collect();
                    names.sort();
                    names.dedup();
                    RepositoryService::list_records_by_names_tx(
                        &mut tx,
                        zone.id,
                        &names,
                        LockLevel::Exclusive,
                    )
                    .await
                }
                ImportMode::Replace | ImportMode::Upsert => {
                    RepositoryService::list_records_tx(&mut tx, zone.id, LockLevel::Exclusive).await
                }
            }
            .map_err(|e| {
                log_error!("Failed to load zone records: {}", e);
                ServiceError::internal("Failed to import zone file".to_string())
            })?;
            timings.load_existing_ms = elapsed_ms(t);

            // Index existing records by owner name so each existing/desired
            // record is reconciled against only same-name rows.
            let t = Instant::now();
            let mut existing_by_name: HashMap<OwnerName, Vec<&Record>> =
                HashMap::with_capacity(existing_records.len());
            for record in existing_records.iter() {
                existing_by_name
                    .entry(record.name.clone())
                    .or_default()
                    .push(record);
            }
            timings.build_index_ms = elapsed_ms(t);

            let t = Instant::now();
            let desired_matches_existing = |e: &Record| {
                desired_by_name
                    .get(&e.name)
                    .is_some_and(|idxs| idxs.iter().any(|&i| desired_matches(e, &desired[i])))
            };
            let desired_key_matches_existing = |e: &Record| {
                desired_by_name.get(&e.name).is_some_and(|idxs| {
                    idxs.iter()
                        .any(|&i| desired[i].prepared.record_type == e.record_type)
                })
            };

            // Deletions implied by the mode.
            let dels: Vec<Record> = match mode {
                ImportMode::Append => Vec::new(),
                ImportMode::Replace => existing_records
                    .iter()
                    .filter(|e| !is_protected(&zone, e) && !desired_matches_existing(e))
                    .cloned()
                    .collect(),
                ImportMode::Upsert => existing_records
                    .iter()
                    .filter(|e| {
                        desired_key_matches_existing(e)
                            && !is_protected(&zone, e)
                            && !desired_matches_existing(e)
                    })
                    .cloned()
                    .collect(),
            };

            // Reconcile TTL only for upsert/replace.
            let reconcile_ttl = matches!(mode, ImportMode::Upsert | ImportMode::Replace);
            let effective_ttl = |ttl: Option<i32>| ttl.unwrap_or(zone.default_ttl);

            let mut unchanged = 0usize;
            let mut updated = 0usize;
            let mut ttl_dels: Vec<Record> = Vec::new();
            let mut adds: Vec<&DesiredRecord> = Vec::new();
            for d in &desired {
                let desired_ttl = effective_ttl(d.prepared.ttl);
                let mut present = false;
                let mut stale = false;
                if let Some(es) = existing_by_name.get(&d.stored_name) {
                    for &e in es {
                        if desired_matches(e, d) {
                            present = true;
                            if reconcile_ttl && e.ttl != desired_ttl {
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
            timings.reconcile_ms = elapsed_ms(t);

            // Validate additions against an in-memory copy so constraint
            // violations are caught without writing anything. Simulated records
            // are indexed by name so each check scans only same-name candidates.
            let t = Instant::now();
            // A DS requires the delegation NS at its name, which the same file
            // may add — and exports sort DS before NS. Validate DS rows last.
            adds.sort_by_key(|add| add.prepared.record_type == RecordType::DS);
            let del_ids: HashSet<i32> = dels.iter().chain(&ttl_dels).map(|d| d.id).collect();
            let mut simulated_by_name: HashMap<OwnerName, Vec<Record>> =
                HashMap::with_capacity(existing_records.len());
            for e in existing_records.iter() {
                if !del_ids.contains(&e.id) {
                    simulated_by_name
                        .entry(e.name.clone())
                        .or_default()
                        .push(e.clone());
                }
            }
            for add in &adds {
                let same_name = simulated_by_name
                    .entry(add.stored_name.clone())
                    .or_default();
                match validate_record_add_constraints_normalized(
                    same_name,
                    &add.stored_name,
                    &add.prepared.record_type,
                    &add.prepared.value,
                    effective_ttl(add.prepared.ttl),
                    add.prepared.priority,
                    None,
                ) {
                    Ok(()) => same_name.push(synthetic_record(
                        &add.stored_name,
                        &add.prepared.record_type,
                        &add.prepared.value,
                        effective_ttl(add.prepared.ttl),
                        add.prepared.priority,
                    )),
                    Err(e) if e.code.http_status() < 500 => {
                        errors.push(format!("{}: {}", add.prepared.owner_name, e.message))
                    }
                    Err(e) => return Err(e),
                }
            }
            // A replace can drop a delegation NS while its DS survives
            // unchanged, so the coupling is re-checked on the final state.
            for (name, rows) in &simulated_by_name {
                if rows.iter().any(|r| r.record_type == RecordType::DS)
                    && !rows.iter().any(|r| r.record_type == RecordType::NS)
                {
                    errors.push(format!(
                        "'{}': DS records require a delegation NS RRset at the same name",
                        name
                    ));
                }
            }
            timings.validate_ms = elapsed_ms(t);

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
                let new_serial = generate_serial(Some(zone.serial))?;

                let t = Instant::now();
                let mut all_dels = dels;
                all_dels.extend(ttl_dels);
                RecordService::delete_records_with_changes_tx(
                    &mut tx, zone.id, new_serial, &all_dels,
                )
                .await?;

                let to_insert: Vec<Record> = adds
                    .iter()
                    .map(|add| Record {
                        id: 0,
                        name: add.stored_name.clone(),
                        record_type: add.prepared.record_type.clone(),
                        value: add.prepared.value.clone(),
                        ttl: effective_ttl(add.prepared.ttl),
                        priority: add.prepared.priority,
                        zone_id: zone.id,
                        created_at: Utc::now(),
                    })
                    .collect();
                RecordService::insert_records_with_changes_tx(
                    &mut tx, zone.id, new_serial, &to_insert,
                )
                .await?;
                timings.db_write_ms = elapsed_ms(t);

                let t = Instant::now();
                // Advance the serial once so IXFR consumers detect the import
                DnssecService::sign_zone_tx(&mut tx, &zone, new_serial).await?;
                ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;
                timings.serial_ms = elapsed_ms(t);
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
        if changed
            && let Err(e) = crate::notify::send_notify_after_update(Some(zone_name.as_str())).await
        {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }
        let notify_ms = elapsed_ms(t);

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
            timings.parse_ms,
            timings.load_zone_ms,
            timings.load_existing_ms,
            timings.normalize_ms,
            timings.build_index_ms,
            timings.reconcile_ms,
            timings.validate_ms,
            timings.db_write_ms,
            timings.serial_ms,
            notify_ms,
            elapsed_ms(t_total),
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
        ttl: add.prepared.ttl.unwrap_or(zone.default_ttl),
        priority: add.prepared.priority,
    }));

    build_record_diff(zone, &before, &after)
}

/// A placeholder record for in-memory comparison only; the negative id keeps it
/// distinct from persisted rows.
fn synthetic_record(
    stored_name: &OwnerName,
    record_type: &RecordType,
    value: &str,
    ttl: i32,
    priority: Option<i32>,
) -> Record {
    Record {
        id: -1,
        name: stored_name.clone(),
        record_type: record_type.clone(),
        value: value.to_string(),
        ttl,
        priority,
        zone_id: 0,
        created_at: Utc::now(),
    }
}
