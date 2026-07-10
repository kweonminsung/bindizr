use chrono::Utc;

use super::{
    RecordService,
    bulk::{PreparedRecord, delete_existing_record_tx, insert_validated_tx, load_zone_tx},
    record_value::record_values_equal,
    validation::{
        normalize_record_owner_name, validate_delete_constraints,
        validate_record_add_constraints_normalized,
    },
    zonefile::parse_zone_file,
};
use crate::{
    error::ServiceError,
    log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{ImportMode, ImportSummary, ImportZoneFileRequest, ImportZoneFileResponse},
    zone::snapshot::save_zone_snapshot_tx,
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

        let mut tx = RepositoryService::begin_tx("Failed to import zone file").await?;

        let apply_result = async {
            let zone = load_zone_tx(&mut tx, zone_name).await?;

            let existing_records = RepositoryService::get_records_by_zone_id_tx(&mut tx, zone.id)
                .await
                .map_err(|e| {
                    log_error!("Failed to load zone records: {}", e);
                    ServiceError::Internal("Failed to import zone file".to_string())
                })?;

            let parsed = parse_zone_file(&request.content, &zone.name, zone.ttl);
            let mut errors = parsed.errors;
            let mut skipped = 0usize;

            // Normalize parsed records and drop duplicates within the file.
            let mut desired: Vec<DesiredRecord> = Vec::new();
            for record in parsed.records {
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
                    Err(ServiceError::BadRequest(msg)) => {
                        errors.push(format!("{}: {}", record.owner_fqdn, msg));
                        continue;
                    }
                    Err(e) => return Err(e),
                };

                let duplicate_in_file = desired.iter().any(|d| {
                    d.stored_name.eq_ignore_ascii_case(&stored_name)
                        && d.prepared.record_type == record.record_type
                        && record_values_equal(
                            &d.prepared.value,
                            d.prepared.priority,
                            &value,
                            record.priority,
                            &record.record_type,
                        )
                });
                if duplicate_in_file {
                    skipped += 1;
                    continue;
                }

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

            let parsed_count = desired.len();

            // Deletions implied by the mode.
            let dels: Vec<Record> = match mode {
                ImportMode::Append => Vec::new(),
                ImportMode::Replace => existing_records
                    .iter()
                    .filter(|e| {
                        !is_protected(&zone, e) && !desired.iter().any(|d| desired_matches(e, d))
                    })
                    .cloned()
                    .collect(),
                ImportMode::Upsert => existing_records
                    .iter()
                    .filter(|e| {
                        let key_in_file = desired.iter().any(|d| {
                            e.name.eq_ignore_ascii_case(&d.stored_name)
                                && e.record_type == d.prepared.record_type
                        });
                        key_in_file
                            && !is_protected(&zone, e)
                            && !desired.iter().any(|d| desired_matches(e, d))
                    })
                    .cloned()
                    .collect(),
            };

            // Additions: desired records not already present.
            let mut unchanged = 0usize;
            let adds: Vec<&DesiredRecord> = desired
                .iter()
                .filter(|d| {
                    let present = existing_records.iter().any(|e| desired_matches(e, d));
                    if present {
                        unchanged += 1;
                    }
                    !present
                })
                .collect();

            // Validate additions against an in-memory copy so constraint
            // violations are caught without writing anything.
            let mut simulated: Vec<Record> = existing_records
                .iter()
                .filter(|e| !dels.iter().any(|d| d.id == e.id))
                .cloned()
                .collect();
            for add in &adds {
                // The owner name was already normalized above, so validate
                // against `stored_name` instead of normalizing a second time.
                match validate_record_add_constraints_normalized(
                    &simulated,
                    &add.prepared.owner_name,
                    &add.stored_name,
                    &add.prepared.record_type,
                    &add.prepared.value,
                    add.prepared.priority,
                    None,
                ) {
                    Ok(()) => simulated.push(synthetic_record(
                        &add.stored_name,
                        &add.prepared.record_type,
                        &add.prepared.value,
                        add.prepared.priority,
                    )),
                    Err(ServiceError::BadRequest(msg)) => {
                        errors.push(format!("{}: {}", add.prepared.owner_name, msg))
                    }
                    Err(e) => return Err(e),
                }
            }

            let summary = ImportSummary {
                parsed: parsed_count,
                added: adds.len(),
                deleted: dels.len(),
                unchanged,
                skipped,
            };

            let will_apply = errors.is_empty() && !dry_run;
            let has_changes = !dels.is_empty() || !adds.is_empty();

            if will_apply && has_changes {
                let new_serial = generate_serial(Some(zone.serial));

                for record in &dels {
                    delete_existing_record_tx(&mut tx, &zone, new_serial, record).await?;
                }
                // Already validated against `simulated` above, so insert directly.
                for add in &adds {
                    insert_validated_tx(
                        &mut tx,
                        &zone,
                        new_serial,
                        &add.stored_name,
                        &add.prepared,
                    )
                    .await?;
                }

                RepositoryService::update_zone_serial_tx(&mut tx, zone.id, new_serial)
                    .await
                    .map_err(|e| {
                        log_error!("Failed to update zone serial: {}", e);
                        ServiceError::Internal("Failed to update zone serial".to_string())
                    })?;

                save_zone_snapshot_tx(&mut tx, &zone, new_serial).await?;
            }

            let response = ImportZoneFileResponse {
                applied: will_apply,
                dry_run,
                summary,
                errors,
            };

            // `zone` is dead after this point, so hand its name over rather than
            // cloning it.
            Ok::<(ImportZoneFileResponse, String, bool), ServiceError>((
                response,
                zone.name,
                will_apply && has_changes,
            ))
        }
        .await;

        let (response, zone_name, changed) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to import zone file").await?;

        log_info!(
            "event=zone_import zone={} mode={:?} applied={} added={} deleted={} unchanged={} skipped={} errors={}",
            zone_name,
            mode,
            response.applied,
            response.summary.added,
            response.summary.deleted,
            response.summary.unchanged,
            response.summary.skipped,
            response.errors.len(),
        );

        if changed && let Err(e) = crate::notify::send_notify_after_update(Some(&zone_name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(response)
    }
}

/// A placeholder record for in-memory comparison only; the negative id keeps it
/// distinct from persisted rows.
fn synthetic_record(
    stored_name: &str,
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
) -> Record {
    Record {
        id: -1,
        name: stored_name.to_string(),
        record_type: record_type.clone(),
        value: value.to_string(),
        ttl: None,
        priority,
        zone_id: 0,
        created_at: Utc::now(),
    }
}
