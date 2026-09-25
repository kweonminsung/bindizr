mod plan;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    time::Instant,
};

use bindizr_core::{
    config::bindizr_config,
    dns::{
        address::is_address_target,
        name::{OwnerName, ZoneName},
        zonefile::{ParsedZoneFile, ZoneFileValue},
    },
};
use bindizr_db::repository::LockLevel;
use chrono::Utc;
use plan::{DesiredRecord, compute_import_plan};

use super::{
    RecordService,
    bulk::PreparedRecord,
    validation::{normalize_record_owner_name, validate_record_add_constraints_normalized},
};
use crate::{
    authorization::Caller,
    dnssec::DnssecService,
    error::ServiceError,
    model::record::{Record, RecordType},
    repository::RepositoryService,
    serial::generate_serial,
    timing::elapsed_ms,
    types::{
        CreateZoneRequest, ImportMode, ImportSummary, ImportZoneRequest, ImportZoneResponse,
        RecordDiff, RecordValueRequest,
    },
    zone::{ZoneService, version::ChangeSubject},
};

/// Outcome of the transactional part of a zone-file import.
struct AppliedImport {
    response: ImportZoneResponse,
    zone_name: ZoneName,
    changed: bool,
    /// This import created the zone, so the catalog gained a member.
    created: bool,
}

/// Per-stage timings, emitted as one debug summary after commit + NOTIFY;
/// `db_write_ms`/`serial_ms` stay zero on a dry run or no-op.
#[derive(Default)]
struct ImportTimings {
    load_zone_ms: f64,
    load_existing_ms: f64,
    parse_ms: f64,
    normalize_ms: f64,
    reconcile_ms: f64,
    validate_ms: f64,
    db_write_ms: f64,
    serial_ms: f64,
}

impl RecordService {
    /// Import records into an existing zone from BIND zone file text or over
    /// AXFR from `from_server`, reconciling them by mode. On apply the zone
    /// serial is incremented once and a single NOTIFY is sent. If any record
    /// fails validation nothing is applied and the errors are returned.
    pub async fn import_zone(
        caller: &Caller,
        zone_name: &str,
        request: &ImportZoneRequest,
    ) -> Result<ImportZoneResponse, ServiceError> {
        caller.authorize_global("import zone files")?;

        let content: Cow<'_, str> = match (&request.content, &request.from_server) {
            (Some(content), None) => Cow::Borrowed(content.as_str()),
            (None, Some(server)) => {
                let server = server.trim();
                if !is_address_target(server) {
                    return Err(ServiceError::invalid_input(
                        "from_server must name one server as host[:port]",
                    ));
                }
                // The zone's existence precedes the outbound fetch, so a
                // mistyped name cannot start a transfer. With `create` there is
                // no zone yet, and the transfer itself refuses an unknown one.
                if !request.create {
                    ZoneService::lookup_by_name(zone_name).await?;
                }
                let content = crate::dns_client::axfr::fetch_zone_file(server, zone_name)
                    .await
                    .map_err(|e| {
                        ServiceError::invalid_input(format!("AXFR from {} failed: {}", server, e))
                    })?;
                Cow::Owned(content)
            }
            (Some(_), Some(_)) => {
                return Err(ServiceError::invalid_input(
                    "give either content or from_server, not both",
                ));
            }
            (None, None) => {
                return Err(ServiceError::invalid_input("give content or from_server"));
            }
        };
        Self::reconcile_zone_file(
            zone_name,
            &content,
            request.mode,
            request.dry_run,
            request.skip_unsupported,
            request.create.then_some(caller),
            &caller.change_subject(),
        )
        .await
    }

    /// Preview or apply a zone-file reconciliation in its own transaction,
    /// creating the zone from the file's SOA when `create_as` says to.
    async fn reconcile_zone_file(
        zone_name: &str,
        content: &str,
        mode: ImportMode,
        dry_run: bool,
        skip_unsupported: bool,
        create_as: Option<&Caller>,
        subject: &ChangeSubject,
    ) -> Result<ImportZoneResponse, ServiceError> {
        let t_total = Instant::now();

        let mut timings = ImportTimings::default();

        let mut tx = RepositoryService::begin_tx("Failed to import zone file").await?;

        let apply_result: Result<AppliedImport, ServiceError> = async {
            let t = Instant::now();
            let mut created = false;
            let zone = match (
                ZoneService::find_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?,
                create_as,
            ) {
                (Some(zone), _) => zone,
                // Created in this transaction, so a dry run rolls it back with
                // the records and an apply commits both at once.
                (None, Some(caller)) => {
                    let soa = ParsedZoneFile::parse(content, zone_name, 0)
                        .soa
                        .ok_or_else(|| {
                            ServiceError::invalid_input(
                                "the zone file carries no SOA to create the zone from; create it with `zone create` first",
                            )
                        })?;
                    created = true;
                    ZoneService::create_tx(
                        &mut tx,
                        caller,
                        &CreateZoneRequest::from_zone_file_soa(zone_name, &soa)?,
                    )
                    .await?
                }
                (None, None) => return Err(ServiceError::zone_not_found(zone_name)),
            };
            timings.load_zone_ms = elapsed_ms(t);

            let t = Instant::now();
            // Relative owners and omitted TTLs must use the zone this transaction locked.
            let parsed = ParsedZoneFile::parse(content, zone.name.as_str(), zone.default_ttl);
            timings.parse_ms = elapsed_ms(t);
            let mut errors = parsed.errors;
            let mut skipped = 0usize;

            // Refusing a whole file over one line it cannot store leaves a
            // zone served elsewhere no way in.
            let skipped_records = if skip_unsupported {
                skipped += parsed.unsupported.len();
                parsed.unsupported
            } else {
                errors.extend(parsed.unsupported);
                Vec::new()
            };

            // Normalize parsed RRs and drop duplicates within the file,
            // indexed by owner name so the dedup check scans only same-name entries.
            let t = Instant::now();
            let mut desired: Vec<DesiredRecord> = Vec::with_capacity(parsed.records.len());
            let mut desired_by_name: HashMap<OwnerName, Vec<usize>> =
                HashMap::with_capacity(parsed.records.len());
            for record in parsed.records {
                let requested = match record.value {
                    ZoneFileValue::Rdata(rdata) => RecordValueRequest::String(rdata),
                    ZoneFileValue::CharacterStrings(segments) => {
                        RecordValueRequest::Segments(segments)
                    }
                };
                let value = match requested.to_encoded_value(&record.record_type, record.priority) {
                    Ok(value) => value,
                    Err(e) => {
                        errors.push(format!("{}: {}", record.owner_fqdn, e));
                        continue;
                    }
                };
                let stored_name = match normalize_record_owner_name(&record.owner_fqdn, &zone.name)
                {
                    Ok(stored_name) => stored_name,
                    Err(e) => {
                        errors.push(format!("{}: {}", record.owner_fqdn, e.message));
                        continue;
                    }
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
                            "{}: {} records with conflicting TTLs {} and {}; records sharing a name and type share one TTL",
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
                        priority: record.record_type.stored_priority(record.priority),
                        record_type: record.record_type,
                        value,
                        ttl: Some(record.ttl),
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
                log::error!("Failed to load zone records: {}", e);
                ServiceError::internal("Failed to import zone file")
            })?;
            timings.load_existing_ms = elapsed_ms(t);

            let effective_ttl = |ttl: Option<i32>| ttl.unwrap_or(zone.default_ttl);

            let t = Instant::now();
            let plan = compute_import_plan(mode, &zone, &existing_records, &desired);
            timings.reconcile_ms = elapsed_ms(t);

            // Validate additions against an in-memory copy so constraint
            // violations are caught without writing anything. Simulated records
            // are indexed by name so each check scans only same-name candidates.
            let t = Instant::now();
            let del_ids: HashSet<i32> = plan.dels.iter().chain(&plan.ttl_dels).map(|d| d.id).collect();
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
            for add in &plan.adds {
                let records_at_name = simulated_by_name
                    .entry(add.stored_name.clone())
                    .or_default();
                match validate_record_add_constraints_normalized(
                    records_at_name,
                    &add.stored_name,
                    &add.prepared.record_type,
                    &add.prepared.value,
                    effective_ttl(add.prepared.ttl),
                    add.prepared.priority,
                    None,
                ) {
                    // In-memory comparison only; the negative id keeps the
                    // placeholder distinct from persisted rows.
                    Ok(()) => records_at_name.push(Record {
                        id: -1,
                        name: add.stored_name.clone(),
                        record_type: add.prepared.record_type.clone(),
                        value: add.prepared.value.clone(),
                        ttl: effective_ttl(add.prepared.ttl),
                        priority: add.prepared.priority,
                        zone_id: 0,
                        created_at: Utc::now(),
                    }),
                    Err(e) => {
                        errors.push(format!("{}: {}", add.prepared.owner_name, e.message))
                    }
                }
            }
            // Mirror of the version-time delegation check, so a dry run
            // reports the violation per name instead of failing the apply.
            for (name, rows) in &simulated_by_name {
                if rows.iter().any(|r| r.record_type == RecordType::DS)
                    && !rows.iter().any(|r| r.record_type == RecordType::NS)
                {
                    errors.push(format!(
                        "'{}': DS records require delegation NS records at the same name",
                        name
                    ));
                }
            }
            timings.validate_ms = elapsed_ms(t);

            let summary = ImportSummary {
                parsed: parsed_count,
                // Additions also carry the re-inserted TTL-reconciled records,
                // which are reported under `updated` instead.
                added: plan.adds.len() - plan.updated,
                deleted: plan.dels.len(),
                updated: plan.updated,
                unchanged: plan.unchanged,
                skipped,
            };

            // Only a valid dry run needs a diff; failed validation must not preview
            // changes that cannot be applied.
            let diff = if dry_run && errors.is_empty() {
                plan.diff(&zone, &existing_records)
            } else {
                RecordDiff::default()
            };

            let will_apply = errors.is_empty() && !dry_run;
            let has_changes = !plan.dels.is_empty() || !plan.adds.is_empty() || !plan.ttl_dels.is_empty();

            // Only a valid, nonempty apply writes rows and advances the serial.
            if will_apply && has_changes {
                let new_serial = generate_serial(Some(zone.serial))?;

                let t = Instant::now();
                let mut all_dels = plan.dels;
                all_dels.extend(plan.ttl_dels);
                RecordService::delete_with_changes_tx(
                    &mut tx, zone.id, new_serial, &all_dels,
                )
                .await?;

                let to_insert: Vec<Record> = plan.adds
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
                RecordService::create_with_changes_tx(
                    &mut tx, zone.id, new_serial, &to_insert,
                )
                .await?;
                timings.db_write_ms = elapsed_ms(t);

                let t = Instant::now();
                DnssecService::sign_zone_tx(&mut tx, &zone, new_serial).await?;
                // Advance the serial once so IXFR consumers detect the import.
                ZoneService::advance_serial_tx(&mut tx, &zone, new_serial, subject).await?;
                timings.serial_ms = elapsed_ms(t);
            }

            let response = ImportZoneResponse {
                applied: will_apply,
                dry_run,
                summary,
                diff,
                errors,
                skipped_records,
            };

            Ok(AppliedImport {
                response,
                zone_name: zone.name,
                changed: will_apply && has_changes,
                created: will_apply && created,
            })
        }
        .await;

        // Only an applied import commits: a dry run and a rejected one both
        // answer `applied: false`, so neither may leave the zone `create` made.
        let discard = dry_run
            || !apply_result
                .as_ref()
                .is_ok_and(|import| import.response.applied);
        let AppliedImport {
            response,
            zone_name,
            changed,
            created,
        } = if discard {
            RepositoryService::discard_tx(tx, apply_result).await?
        } else {
            RepositoryService::finish_tx(tx, apply_result, "Failed to import zone file").await?
        };

        log::info!(
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
        // The catalog goes first: a secondary that has not seen the new member
        // there cannot act on the zone's own NOTIFY below.
        let config = bindizr_config();
        if created
            && let Err(e) =
                crate::notify::send_notify_after_update(Some(&config.dns.catalog_zone_name)).await
        {
            log::warn!(
                "Failed to send NOTIFY for {}: {}",
                config.dns.catalog_zone_name,
                e
            );
        }
        // Notify after commit only when the import changed the served zone.
        if changed
            && let Err(e) = crate::notify::send_notify_after_update(Some(zone_name.as_str())).await
        {
            log::warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }
        let notify_ms = elapsed_ms(t);

        // Per-stage breakdown for profiling; debug-gated so it stays out of
        // normal (info-level) runs. NOTIFY is inline only in sync apply mode.
        log::debug!(
            "event=zone_import_timing zone={} mode={:?} parsed={} applied={} parse_ms={:.1} \
             load_zone_ms={:.1} load_existing_ms={:.1} normalize_ms={:.1} \
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
