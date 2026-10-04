mod plan;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    time::Instant,
};

use bindizr_core::{
    dns::{
        Ttl,
        address::is_address_target,
        name::{OwnerName, ZoneName},
        record::SoaMailbox,
        zonefile::{ParsedZoneFile, ZoneFileSoa, ZoneFileValue},
    },
    model::{record::RecordId, role_grant::Action, zone::ZoneId},
};
use bindizr_db::LockLevel;
use chrono::Utc;
use plan::{DesiredRecord, ImportPlan};

use super::{
    bulk::PreparedRecord,
    validation::{normalize_record_owner_name, validate_record_add_constraints_normalized},
};
use crate::{
    Context,
    authorization::Caller,
    dnssec,
    error::ServiceError,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    serial::{generate_serial, validate_initial_serial},
    time::elapsed_ms,
    transaction,
    types::{
        CreateZoneRequest, ImportMode, ImportSummary, ImportZoneRequest, ImportZoneResponse,
        RecordDiff, RecordValue, Run,
    },
    zone,
};

/// The request a zone file's SOA describes. The serial carries over so
/// secondaries holding the old primary's serial accept the transfer; one past
/// bindizr's ceiling starts fresh instead.
fn build_create_zone_request(
    zone_name: &ZoneName,
    soa: &ZoneFileSoa,
) -> Result<CreateZoneRequest, ServiceError> {
    let rname = SoaMailbox::from_encoded(soa.rname.trim_end_matches('.'))
        .to_email()
        .map_err(|e| {
            ServiceError::invalid_input(format!("the SOA's RNAME is not an address: {}", e))
        })?;
    Ok(CreateZoneRequest {
        dry_run: false,
        // The zone file carries its own NS records.
        apex_ns: false,
        name: zone_name.to_string(),
        mname: soa.mname.clone(),
        rname,
        default_ttl: None,
        // The file's serial only if a zone may start from it, so an
        // unusable one generates a fresh serial instead of failing.
        serial: validate_initial_serial(soa.serial)
            .is_ok()
            .then_some(soa.serial),
        refresh: Some(i32::from(soa.refresh)),
        retry: Some(i32::from(soa.retry)),
        expire: Some(i32::from(soa.expire)),
        minimum_ttl: Some(i32::from(soa.minimum_ttl)),
        description: None,
    })
}

/// Outcome of the transactional part of a zone-file import.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedImport {
    response: ImportZoneResponse,
    zone_name: ZoneName,
    changed: bool,
    /// This import created the zone, so the catalog gained a member.
    created: bool,
}

/// Per-stage timings, emitted as one debug summary after commit + NOTIFY;
/// `db_write_ms`/`serial_ms` stay zero on a dry run or no-op.
#[derive(Default, Debug, Clone, PartialEq)]
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

/// Import zone-file or AXFR records by mode; any validation failure rejects the whole import.
/// Applying advances the serial once and sends one NOTIFY.
pub async fn import_zone(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    request: &ImportZoneRequest,
) -> Result<ImportZoneResponse, ServiceError> {
    let mode = request
        .mode
        .parse::<ImportMode>()
        .map_err(ServiceError::invalid_input)?;

    let content: Cow<'_, str> = match (&request.content, &request.from_server) {
        (Some(content), None) => Cow::Borrowed(content.as_str()),
        (None, Some(server)) => {
            let server = server.trim();
            if !is_address_target(server) {
                return Err(ServiceError::invalid_input(
                    "from_server must name one server as host[:port]",
                ));
            }
            // Checked before the outbound fetch so neither a mistyped name nor
            // an unauthorized role starts a transfer; the transaction decides
            // again. With `create` there is no zone yet.
            if request.create {
                caller.authorize_action(Action::ZoneCreate)?;
            } else {
                let zone = zone::lookup_by_name(cx, zone_name).await?;
                authorize_import(caller, mode, &zone)?;
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
    reconcile_zone_file(cx, caller, zone_name, &content, request, mode).await
}

/// Authorize each record action the import mode performs over the zone whole.
fn authorize_import(caller: &Caller, mode: ImportMode, zone: &Zone) -> Result<(), ServiceError> {
    let actions: &[Action] = match mode {
        ImportMode::Append => &[Action::RecordCreate],
        ImportMode::Upsert | ImportMode::Replace => &[Action::RecordCreate, Action::RecordDelete],
    };
    for action in actions {
        caller.authorize_whole_zone(*action, zone)?;
    }
    Ok(())
}

/// Preview or apply a zone-file reconciliation in its own transaction; a
/// missing zone is created from the file's SOA as `caller` when the request
/// says to.
async fn reconcile_zone_file(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    content: &str,
    request: &ImportZoneRequest,
    mode: ImportMode,
) -> Result<ImportZoneResponse, ServiceError> {
    let attribution = caller.change_attribution();
    let run = Run::from_dry_run(request.dry_run);
    let t_total = Instant::now();

    let mut timings = ImportTimings::default();

    let mut tx = transaction::begin_tx(cx, "failed to import zone file").await?;

    let apply_result: Result<AppliedImport, ServiceError> = async {
        let t = Instant::now();
        let mut created = false;
        let zone = match (
            zone::find_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?,
            request.create,
        ) {
            (Some(zone), _) => zone,
            // Created in this transaction, so a dry run rolls it back with
            // the records and an apply commits both at once.
            (None, true) => {
                let soa = ParsedZoneFile::parse(content, zone_name, Ttl::from_secs(0))
                    .soa
                    .ok_or_else(|| {
                        ServiceError::invalid_input(
                            "the zone file carries no SOA to create the zone from; create it with `zone create` first",
                        )
                    })?;
                created = true;
                zone::create_tx(
                    &mut tx,
                    cx,
                    caller,
                    &build_create_zone_request(zone_name, &soa)?,
                )
                .await?
            }
            (None, false) => return Err(ServiceError::zone_not_found(zone_name)),
        };
        authorize_import(caller, mode, &zone)?;
        timings.load_zone_ms = elapsed_ms(t);

        let t = Instant::now();
        // Relative owners and omitted TTLs must use the zone this transaction locked.
        let parsed = ParsedZoneFile::parse(content, &zone.name, zone.default_ttl);
        timings.parse_ms = elapsed_ms(t);
        let mut errors = parsed.errors;
        let mut skipped = 0usize;

        // Refusing a whole file over one line it cannot store leaves a
        // zone served elsewhere no way in.
        let skipped_records = if request.skip_unsupported {
            skipped += parsed.unsupported.len();
            parsed.unsupported
        } else {
            errors.extend(parsed.unsupported);
            Vec::new()
        };

        // Normalize parsed records and drop duplicates within the file,
        // indexed by owner name so the dedup check scans only same-name entries.
        let t = Instant::now();
        let mut desired: Vec<DesiredRecord> = Vec::with_capacity(parsed.records.len());
        let mut desired_by_name: HashMap<OwnerName, Vec<usize>> =
            HashMap::with_capacity(parsed.records.len());
        for record in parsed.records {
            let requested = match record.value {
                ZoneFileValue::Rdata(rdata) => RecordValue::Text(rdata),
                ZoneFileValue::Segments(segments) => {
                    RecordValue::Segments(segments)
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
                    errors.push(format!("{}: {}", record.owner_fqdn, e));
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

            desired_by_name
                .entry(name_key)
                .or_default()
                .push(desired.len());
            desired.push(DesiredRecord {
                prepared: PreparedRecord {
                    raw_name: record.owner_fqdn,
                    priority: record.record_type.stored_priority(record.priority),
                    record_type: record.record_type,
                    value,
                    ttl: Some(record.ttl),
                },
                name: stored_name,
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
                    desired.iter().map(|d| d.name.clone()).collect();
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
        .map_err(|e| {
            log::error!("Failed to load zone records: {}", e);
            ServiceError::internal_with_source("failed to import zone file", e)
        })?;
        timings.load_existing_ms = elapsed_ms(t);

        let effective_ttl = |ttl: Option<Ttl>| ttl.unwrap_or(zone.default_ttl);

        let t = Instant::now();
        let plan = ImportPlan::compute(mode, &zone, &existing_records, &desired);
        timings.reconcile_ms = elapsed_ms(t);

        // Validate additions against an in-memory copy so constraint
        // violations are caught without writing anything. Simulated records
        // are indexed by name so each check scans only same-name candidates.
        let t = Instant::now();
        let del_ids: HashSet<RecordId> = plan.dels.iter().chain(&plan.ttl_dels).map(|d| d.id).collect();
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
                .entry(add.name.clone())
                .or_default();
            match validate_record_add_constraints_normalized(
                records_at_name,
                &add.name,
                &add.prepared.record_type,
                &add.prepared.value,
                effective_ttl(add.prepared.ttl),
                add.prepared.priority,
                None,
            ) {
                // In-memory comparison only; the negative id keeps the
                // placeholder distinct from persisted rows.
                Ok(()) => records_at_name.push(Record {
                    id: RecordId::from(-1),
                    name: add.name.clone(),
                    record_type: add.prepared.record_type,
                    value: add.prepared.value.clone(),
                    ttl: effective_ttl(add.prepared.ttl),
                    priority: add.prepared.priority,
                    zone_id: ZoneId::UNWRITTEN,
                    created_at: Utc::now(),
                }),
                Err(e) => {
                    errors.push(format!("{}: {}", add.prepared.raw_name, e))
                }
            }
        }
        // Mirror of the version-time delegation check, so a dry run
        // reports the violation per name instead of failing the apply.
        for (name, rows) in &simulated_by_name {
            if rows.iter().any(|r| r.record_type == RecordType::Ds)
                && !rows.iter().any(|r| r.record_type == RecordType::Ns)
            {
                errors.push(format!(
                    "'{}': DS records require delegation NS records at the same name",
                    name
                ));
            }
        }
        timings.validate_ms = elapsed_ms(t);

        let summary = ImportSummary {
            parsed: parsed_count as u64,
            // Additions also carry the re-inserted TTL-reconciled records,
            // which are reported under `updated` instead.
            added: (plan.adds.len() - plan.updated) as u64,
            deleted: plan.dels.len() as u64,
            updated: plan.updated as u64,
            unchanged: plan.unchanged as u64,
            skipped: skipped as u64,
        };

        // Only a valid dry run needs a diff; failed validation must not preview
        // changes that cannot be applied.
        let diff = if run.is_dry_run() && errors.is_empty() {
            plan.diff(caller, &zone, &existing_records)
        } else {
            RecordDiff::default()
        };

        let will_apply = errors.is_empty() && !run.is_dry_run();
        let has_changes = !plan.dels.is_empty() || !plan.adds.is_empty() || !plan.ttl_dels.is_empty();

        // Only a valid, nonempty apply writes rows and advances the serial.
        if will_apply && has_changes {
            let new_serial = generate_serial(Some(zone.serial))?;

            let t = Instant::now();
            let mut all_dels = plan.dels;
            all_dels.extend(plan.ttl_dels);
            super::delete_with_changes_tx(
                &mut tx, zone.id, new_serial, &all_dels,
            )
            .await?;

            let to_insert: Vec<Record> = plan.adds
                .iter()
                .map(|add| Record {
                    id: RecordId::UNWRITTEN,
                    name: add.name.clone(),
                    record_type: add.prepared.record_type,
                    value: add.prepared.value.clone(),
                    ttl: effective_ttl(add.prepared.ttl),
                    priority: add.prepared.priority,
                    zone_id: zone.id,
                    created_at: Utc::now(),
                })
                .collect();
            super::create_with_changes_tx(
                &mut tx, zone.id, new_serial, &to_insert,
            )
            .await?;
            timings.db_write_ms = elapsed_ms(t);

            let t = Instant::now();
            dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
            // Advance the serial once so IXFR consumers detect the import.
            zone::advance_serial_tx(&mut tx, cx, &zone, new_serial, attribution).await?;
            timings.serial_ms = elapsed_ms(t);
        }

        let response = ImportZoneResponse {
            applied: will_apply,
            dry_run: run.is_dry_run(),
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
    let discard = run.is_dry_run()
        || !apply_result
            .as_ref()
            .is_ok_and(|import| import.response.applied);
    let AppliedImport {
        response,
        zone_name,
        changed,
        created,
    } = if discard {
        transaction::discard_tx(tx, apply_result).await?
    } else {
        transaction::finish_tx(tx, apply_result, "failed to import zone file").await?
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
    let config = cx.config();
    if created {
        crate::notify::notify_after_update(cx, &config.dns.catalog_zone_name).await;
    }
    // Notify after commit only when the import changed the served zone.
    if changed {
        crate::notify::notify_after_update(cx, &zone_name).await;
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
