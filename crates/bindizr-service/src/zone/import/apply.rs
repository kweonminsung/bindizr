//! Validate and apply one imported snapshot under its zone lock, then notify after commit.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use bindizr_core::dns::Ttl;
use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::dns::record::SoaMailbox;
use bindizr_core::dns::zonefile::{ParsedZoneFile, ZoneFileSoa, ZoneFileValue};
use bindizr_core::model::record::RecordId;
use bindizr_core::model::zone::ZoneId;
use bindizr_db::LockLevel;
use chrono::Utc;

use super::plan::{DesiredRecord, ImportPlan};
use super::{ImportOptions, ImportSource, MissingZoneAction};
use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::model::record::{Record, RecordData, RecordKey, RecordType};
use crate::model::zone::Zone;
use crate::record::validation;
use crate::types::{
    ImportMode, ImportZoneResponse, ImportZoneSummaryResponse, RecordDiffResponse, RecordValue,
};
use crate::zone::diff;
use crate::{Context, dnssec, record, serial, time, transaction, ttl, zone};

/// Resolve a new zone from the imported SOA and configured creation defaults.
fn prepare_zone(
    cx: &Context,
    zone_name: &ZoneName,
    soa: &ZoneFileSoa,
    default_ttl: Ttl,
) -> Result<Zone, ServiceError> {
    zone::validation::reject_catalog_zone_name(cx, zone_name)?;
    let rname = SoaMailbox::from_encoded(&soa.rname)
        .to_email()
        .map_err(|error| {
            ServiceError::invalid_input(format!("the SOA's RNAME is not an address: {}", error))
        })?;
    let normalized = zone::validation::normalize_soa(&soa.mname, &rname, i64::from(default_ttl))?;

    Ok(Zone {
        id: ZoneId::UNWRITTEN,
        name: zone_name.clone(),
        mname: normalized.mname,
        rname: normalized.rname,
        default_ttl: normalized.ttl,
        serial: soa.serial,
        refresh: ttl::validate_soa_interval(i32::from(soa.refresh), "refresh")?,
        retry: ttl::validate_soa_interval(i32::from(soa.retry), "retry")?,
        expire: ttl::validate_soa_interval(i32::from(soa.expire), "expire")?,
        minimum_ttl: ttl::validate_minimum_ttl(i64::from(soa.minimum_ttl))?,
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    })
}

/// Outcome of the transactional part of a zone-file import.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ApplyImportResult {
    response: ImportZoneResponse,
    zone_name: ZoneName,
    changed: bool,
    /// This import created the zone, so the catalog gained a member.
    created: bool,
}

/// Per-stage timings, emitted as one debug summary after commit + NOTIFY;
/// `db_write_ms`/`serial_ms` stay zero on a dry run or no-op.
#[derive(Default, Debug, Clone, Copy, PartialEq)]
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

/// Preview or apply an import atomically, creating a missing zone from its SOA when requested.
pub(crate) async fn apply_import(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    source: ImportSource<'_>,
    options: ImportOptions,
) -> Result<ImportZoneResponse, ServiceError> {
    let ImportOptions {
        mode,
        run,
        missing_zone_action,
    } = options;
    let total_started = Instant::now();

    let mut timings = ImportTimings::default();

    let mut tx = transaction::begin_tx(cx, "failed to import zone file").await?;

    let apply_result: Result<ApplyImportResult, ServiceError> = async {
        let started = Instant::now();

        let existing = zone::find_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        let zone_missing = existing.is_none();
        let default_ttl = if let Some(zone) = &existing {
            super::authorize_import(caller, mode, zone)?;
            zone.default_ttl
        } else if missing_zone_action == MissingZoneAction::Create {
            super::authorize_new_zone_import(caller, mode)?;
            cx.config().dns.zone_defaults.ttl
        } else {
            return Err(ServiceError::zone_not_found(zone_name));
        };
        timings.load_zone_ms = time::elapsed_ms(started);

        let started = Instant::now();
        let parsed = match source {
            ImportSource::Text(content) => ParsedZoneFile::parse(content, zone_name, default_ttl),
            ImportSource::Transfer(parsed) => parsed,
        };
        let mut zone = match existing {
            Some(zone) => zone,
            None => {
                let soa = parsed.soa.as_ref().ok_or_else(|| ServiceError::invalid_input(
                    "the zone file carries no SOA to create the zone from; create it with `zone create` first",
                ))?;
                prepare_zone(cx, zone_name, soa, default_ttl)?
            }
        };
        timings.parse_ms = time::elapsed_ms(started);
        let mut errors = parsed.errors;
        let mut skipped = 0usize;

        // Normalize parsed records and drop duplicates within the file by identity.
        let started = Instant::now();
        let mut desired: Vec<DesiredRecord> = Vec::with_capacity(parsed.records.len());
        let mut desired_by_key: HashMap<RecordKey, usize> =
            HashMap::with_capacity(parsed.records.len());

        for record in parsed.records {
            let requested = match record.value {
                ZoneFileValue::Rdata(rdata) if record.record_type == RecordType::Txt => {
                    RecordValue::Presentation { presentation: rdata }
                }
                ZoneFileValue::Rdata(rdata) => RecordValue::Text(rdata),
                ZoneFileValue::Segments(segments) => RecordValue::Segments(segments),
            };
            let value = match requested.to_encoded_value(&record.record_type, record.priority) {
                Ok(value) => value,
                Err(error) => {
                    errors.push(format!("{}: {}", record.owner_fqdn, error));
                    continue;
                }
            };
            let stored_name = match validation::normalize_record_owner_name(&record.owner_fqdn, &zone.name) {
                Ok(stored_name) => stored_name,
                Err(error) => {
                    errors.push(format!("{}: {}", record.owner_fqdn, error));
                    continue;
                }
            };

            let data = RecordData {
                name: stored_name,
                priority: record.record_type.stored_priority(record.priority),
                record_type: record.record_type,
                value,
                ttl: record.ttl,
            };
            let key = data.match_key();

            if let Some(&kept) = desired_by_key.get(&key) {
                let kept_ttl = desired[kept].data.ttl;
                let this_ttl = record.ttl;

                // The same record at two TTLs is a mixed-TTL record set (RFC 2181,
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

            desired_by_key.insert(key, desired.len());
            desired.push(DesiredRecord {
                source_name: record.owner_fqdn,
                data,
            });
        }

        timings.normalize_ms = time::elapsed_ms(started);
        let parsed_count = desired.len();

        // Append checks only matching owners; replace/upsert need all rows to find deletions.
        let started = Instant::now();

        let existing_records = if zone_missing {
            Ok(Vec::new())
        } else {
            match mode {
                ImportMode::Append => {
                    let mut names: Vec<OwnerName> =
                        desired.iter().map(|desired_record| desired_record.data.name.clone()).collect();
                    names.sort();
                    names.dedup();

                    bindizr_db::record::list_by_names_tx(
                        &mut tx,
                        zone.id,
                        &names,
                        LockLevel::Exclusive,
                    )
                    .await
                }
                ImportMode::Replace | ImportMode::Upsert => {
                    bindizr_db::record::list_tx(&mut tx, zone.id, LockLevel::Exclusive).await
                }
            }
        }
        .map_err(|error| {
            log::error!("Failed to load zone records: {}", error);
            ServiceError::internal_with_source("failed to import zone file", error)
        })?;

        timings.load_existing_ms = time::elapsed_ms(started);

        let started = Instant::now();
        let plan = ImportPlan::compute(mode, &existing_records, &desired);
        timings.reconcile_ms = time::elapsed_ms(started);

        let mut all_deletes = plan.deletes.clone();
        all_deletes.extend_from_slice(&plan.ttl_deletes);
        let mut to_insert: Vec<Record> = plan
            .adds
            .iter()
            .map(|desired_record| Record {
                id: RecordId::UNWRITTEN,
                name: desired_record.data.name.clone(),
                record_type: desired_record.data.record_type,
                value: desired_record.data.value.clone(),
                ttl: desired_record.data.ttl,
                priority: desired_record.data.priority,
                zone_id: zone.id,
                created_at: Utc::now(),
            })
            .collect();

        // Validate additions without writes, indexing simulated records by owner for conflict checks.
        let started = Instant::now();
        let deleted_ids: HashSet<RecordId> = all_deletes.iter().map(|record| record.id).collect();
        let mut simulated_by_name: HashMap<OwnerName, Vec<Record>> =
            HashMap::with_capacity(existing_records.len());

        for record in &existing_records {
            if !deleted_ids.contains(&record.id) {
                simulated_by_name
                    .entry(record.name.clone())
                    .or_default()
                    .push(record.clone());
            }
        }

        for (desired_record, candidate) in plan.adds.iter().zip(&to_insert) {
            let records_at_name = simulated_by_name
                .entry(desired_record.data.name.clone())
                .or_default();

            match validation::validate_record_constraints(
                records_at_name,
                &desired_record.data.name,
                &desired_record.data.record_type,
                &desired_record.data.value,
                desired_record.data.ttl,
                desired_record.data.priority,
                None,
            ) {
                Ok(()) => records_at_name.push(candidate.clone()),
                Err(error) => errors.push(format!("{}: {}", desired_record.source_name, error)),
            }
        }

        if errors.is_empty()
            && let Err(error) =
                zone::validate_record_changes_tx(&mut tx, &zone, &all_deletes, &to_insert).await
        {
            if error.code().is_internal() {
                return Err(error);
            }
            errors.push(error.to_string());
        }

        timings.validate_ms = time::elapsed_ms(started);

        let summary = ImportZoneSummaryResponse {
            parsed: parsed_count as u64,
            // Additions also carry the re-inserted TTL-reconciled records,
            // which are reported under `updated` instead.
            added: (plan.adds.len() - plan.updated) as u64,
            deleted: plan.deletes.len() as u64,
            updated: plan.updated as u64,
            unchanged: plan.unchanged as u64,
            skipped: skipped as u64,
        };

        // Only a valid dry run needs a diff; failed validation must not preview
        // changes that cannot be applied.
        let diff = if run.is_dry_run() && errors.is_empty() {
            let deleted_ids: HashSet<RecordId> = plan
                .deletes
                .iter()
                .chain(&plan.ttl_deletes)
                .map(|record| record.id)
                .collect();

            let before = caller.readable_records(
                zone.id,
                existing_records.iter().cloned().map(RecordData::from),
            );
            let mut after = caller.readable_records(
                zone.id,
                existing_records
                    .iter()
                    .filter(|record| !deleted_ids.contains(&record.id))
                    .cloned()
                    .map(RecordData::from),
            );

            for desired_record in &plan.adds {
                after.push_written(desired_record.data.clone());
            }

            diff::build_record_diff(&zone, &before, &after)
        } else {
            RecordDiffResponse::default()
        };

        let will_apply = errors.is_empty() && !run.is_dry_run();
        let has_changes = !plan.deletes.is_empty() || !plan.adds.is_empty() || !plan.ttl_deletes.is_empty();

        let new_serial = if has_changes && errors.is_empty() {
            serial::generate_serial(Some(zone.serial))
        } else {
            zone.serial
        };

        if will_apply && zone_missing {
            zone = zone::create_tx(&mut tx, zone).await?;
            for record in &mut to_insert {
                record.zone_id = zone.id;
            }
            zone::save_version_tx(&mut tx, &zone, zone.serial, caller.change_origin()).await?;
        }

        if will_apply && has_changes {
            let started = Instant::now();

            record::delete_with_changes_tx(&mut tx, zone.id, new_serial, &all_deletes).await?;
            record::create_with_changes_tx(&mut tx, zone.id, new_serial, &to_insert).await?;

            timings.db_write_ms = time::elapsed_ms(started);

            let started = Instant::now();

            dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
            zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_origin()).await?;

            timings.serial_ms = time::elapsed_ms(started);
        }

        let response = ImportZoneResponse {
            applied: will_apply,
            dry_run: run.is_dry_run(),
            summary,
            diff,
            errors,
        };

        Ok(ApplyImportResult {
            response,
            zone_name: zone.name,
            changed: will_apply && has_changes,
            created: will_apply && zone_missing,
        })
    }
    .await;

    let ApplyImportResult {
        response,
        zone_name,
        changed,
        created,
    } = transaction::finish_tx(tx, apply_result, "failed to import zone file").await?;

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

    let started = Instant::now();

    // The catalog goes first: a secondary that has not seen the new member
    // there cannot act on the zone's own NOTIFY below.
    cx.metrics()
        .track_serial_bumps(u64::from(created) + u64::from(changed));
    let config = cx.config();

    if created {
        crate::notify::notify_after_update(cx, &config.dns.catalog_zone_name).await;
    }

    // Notify after commit only when the import changed the served zone.
    if changed {
        crate::notify::notify_after_update(cx, &zone_name).await;
    }

    let notify_ms = time::elapsed_ms(started);

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
        time::elapsed_ms(total_started),
    );

    Ok(response)
}
