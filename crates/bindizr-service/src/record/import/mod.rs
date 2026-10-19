mod plan;

use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

use bindizr_core::{
    dns::{
        Ttl,
        address::is_address_target,
        extract_member_zones,
        name::{OwnerName, ZoneName},
        record::SoaMailbox,
        zonefile::{ParsedZoneFile, ZoneFileSoa, ZoneFileValue},
    },
    model::{record::RecordId, role_grant::Action, zone::ZoneId},
};
use bindizr_db::LockLevel;
use chrono::Utc;
use plan::{DesiredRecord, ImportPlan};

use super::validation::{normalize_record_owner_name, validate_record_constraints};
use crate::{
    Context,
    authorization::Caller,
    dnssec,
    error::ServiceError,
    model::{
        record::{Record, RecordData, RecordKey, RecordType},
        zone::Zone,
    },
    serial::generate_serial,
    time::elapsed_ms,
    transaction,
    ttl::{validate_minimum_ttl, validate_soa_interval},
    types::{
        ErrorResponse, ImportMode, ImportResult, ImportZoneRequest, ImportZoneResponse,
        ImportZoneSummaryResponse, ImportZonesItemResponse, ImportZonesRequest,
        ImportZonesResponse, ImportZonesSummaryResponse, RecordDiffResponse, RecordValue, Run,
    },
    zone,
};

/// Resolve a new zone from the imported SOA and configured creation defaults.
fn prepare_zone(
    cx: &Context,
    zone_name: &ZoneName,
    soa: &ZoneFileSoa,
    default_ttl: Ttl,
) -> Result<Zone, ServiceError> {
    zone::validation::reject_catalog_zone_name(cx, zone_name)?;
    let rname = SoaMailbox::from_encoded(soa.rname.trim_end_matches('.'))
        .to_email()
        .map_err(|e| {
            ServiceError::invalid_input(format!("the SOA's RNAME is not an address: {}", e))
        })?;
    let normalized = zone::validation::normalize_soa(&soa.mname, &rname, i64::from(default_ttl))?;
    Ok(Zone {
        id: ZoneId::UNWRITTEN,
        name: zone_name.clone(),
        mname: normalized.mname,
        rname: normalized.rname,
        default_ttl: normalized.ttl,
        serial: soa.serial,
        refresh: validate_soa_interval(i32::from(soa.refresh), "refresh")?,
        retry: validate_soa_interval(i32::from(soa.retry), "retry")?,
        expire: validate_soa_interval(i32::from(soa.expire), "expire")?,
        minimum_ttl: validate_minimum_ttl(i64::from(soa.minimum_ttl))?,
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    })
}

/// Text needs the locked zone's default TTL; AXFR carries every TTL explicitly.
#[derive(Debug)]
enum ImportSource<'a> {
    Text(&'a str),
    Transfer(ParsedZoneFile),
}

/// Outcome of the transactional part of a zone-file import.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconcileResult {
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

    // Checked before any fetch or parse: with `create` there is no zone yet,
    // and only an all-zones grant will reach the one made.
    if request.create {
        caller.authorize_action(Action::ZoneCreate)?;
        for action in import_actions(mode) {
            caller.authorize_all_whole_zones(*action)?;
        }
    }

    let source = match (&request.content, &request.from_server) {
        (Some(content), None) => ImportSource::Text(content),
        (None, Some(server)) => {
            let server = server.trim();
            if !is_address_target(server) {
                return Err(ServiceError::invalid_input(
                    "from_server must name one server as host[:port]",
                ));
            }
            // Reject invalid or unauthorized requests before AXFR; recheck in the transaction.
            if !request.create {
                let zone = zone::lookup_by_name(cx, zone_name).await?;
                authorize_import(caller, mode, &zone)?;
            }
            let records =
                crate::dns_client::axfr::fetch_zone(server, zone_name, &cx.config().dns.import)
                    .await
                    .map_err(|e| {
                        ServiceError::invalid_input(format!("AXFR from {} failed: {}", server, e))
                    })?;
            ImportSource::Transfer(ParsedZoneFile::from_transfer(&records, zone_name))
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
    reconcile(cx, caller, zone_name, source, request, mode).await
}

/// Import the zones named, or the source catalog's members, from one
/// server, each as `import_zone` would in its own transaction; a rejected
/// or failed zone is reported beside the rest.
pub async fn import_zones(
    cx: &Context,
    caller: &Caller,
    request: &ImportZonesRequest,
) -> Result<ImportZonesResponse, ServiceError> {
    let mode = request
        .mode
        .parse::<ImportMode>()
        .map_err(ServiceError::invalid_input)?;
    let server = request.from_server.trim();
    if !is_address_target(server) {
        return Err(ServiceError::invalid_input(
            "from_server must name one server as host[:port]",
        ));
    }
    // Checked once, before any transfer: every zone's `create` would fail alike.
    if request.create {
        caller.authorize_action(Action::ZoneCreate)?;
        for action in import_actions(mode) {
            caller.authorize_all_whole_zones(*action)?;
        }
    }
    let zone_names = match (&request.zone_names, &request.from_catalog) {
        (Some(names), None) => normalize_zone_names(names)?,
        (None, Some(catalog)) => {
            // A catalog names every zone its server provisions, so reading it
            // through Bindizr is an all-zones act.
            for action in import_actions(mode) {
                caller.authorize_all_whole_zones(*action)?;
            }
            let catalog = zone::normalize_name(catalog)?;
            let records =
                crate::dns_client::axfr::fetch_zone(server, &catalog, &cx.config().dns.import)
                    .await
                    .map_err(|e| {
                        ServiceError::invalid_input(format!(
                            "AXFR of catalog {} from {} failed: {}",
                            catalog, server, e
                        ))
                    })?;
            extract_member_zones(&records, &catalog).map_err(|e| {
                ServiceError::invalid_input(format!(
                    "catalog {} from {} cannot be read: {}",
                    catalog, server, e
                ))
            })?
        }
        (Some(_), Some(_)) => {
            return Err(ServiceError::invalid_input(
                "give either zone_names or from_catalog, not both",
            ));
        }
        (None, None) => {
            return Err(ServiceError::invalid_input(
                "give zone_names or from_catalog",
            ));
        }
    };

    let single = ImportZoneRequest {
        content: None,
        from_server: Some(server.to_string()),
        mode: mode.as_str().to_owned(),
        dry_run: request.dry_run,
        skip_unsupported: request.skip_unsupported,
        create: request.create,
    };
    let mut summary = ImportZonesSummaryResponse {
        zones: zone_names.len() as u64,
        ok: 0,
        rejected: 0,
        failed: 0,
    };
    let mut zones = Vec::with_capacity(zone_names.len());
    for zone_name in &zone_names {
        let (result, import, error) = match import_zone(cx, caller, zone_name, &single).await {
            Ok(import) if import.was_rejected() => (ImportResult::Rejected, Some(import), None),
            Ok(import) => (ImportResult::Ok, Some(import), None),
            Err(e) => (ImportResult::Failed, None, Some(ErrorResponse::from(&e))),
        };
        match result {
            ImportResult::Ok => summary.ok += 1,
            ImportResult::Rejected => summary.rejected += 1,
            ImportResult::Failed => summary.failed += 1,
        }
        zones.push(ImportZonesItemResponse {
            zone_name: zone_name.to_string(),
            result,
            import,
            error,
        });
    }
    log::info!(
        "event=zones_import server={} mode={:?} dry_run={} zones={} ok={} rejected={} failed={}",
        server,
        mode,
        request.dry_run,
        summary.zones,
        summary.ok,
        summary.rejected,
        summary.failed,
    );
    Ok(ImportZonesResponse {
        dry_run: request.dry_run,
        summary,
        zones,
    })
}

/// The zones a bulk import names, in request order without repeats.
fn normalize_zone_names(names: &[String]) -> Result<Vec<ZoneName>, ServiceError> {
    if names.is_empty() {
        return Err(ServiceError::invalid_input(
            "zone_names must name at least one zone",
        ));
    }
    let mut zone_names: Vec<ZoneName> = Vec::with_capacity(names.len());
    let mut seen: HashSet<ZoneName> = HashSet::with_capacity(names.len());
    for name in names {
        let zone_name = zone::normalize_name(name)?;
        if seen.insert(zone_name.clone()) {
            zone_names.push(zone_name);
        }
    }
    Ok(zone_names)
}

/// The record actions an import mode performs.
fn import_actions(mode: ImportMode) -> &'static [Action] {
    match mode {
        ImportMode::Append => &[Action::RecordCreate],
        ImportMode::Upsert | ImportMode::Replace => &[Action::RecordCreate, Action::RecordDelete],
    }
}

/// Authorize each record action the import mode performs over the zone whole.
fn authorize_import(caller: &Caller, mode: ImportMode, zone: &Zone) -> Result<(), ServiceError> {
    for action in import_actions(mode) {
        caller.authorize_whole_zone(*action, zone)?;
    }
    Ok(())
}

/// Preview or apply an import atomically, creating a missing zone from its SOA when requested.
async fn reconcile(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    source: ImportSource<'_>,
    request: &ImportZoneRequest,
    mode: ImportMode,
) -> Result<ImportZoneResponse, ServiceError> {
    let run = Run::from_dry_run(request.dry_run);
    let t_total = Instant::now();

    let mut timings = ImportTimings::default();

    let mut tx = transaction::begin_tx(cx, "failed to import zone file").await?;

    let apply_result: Result<ReconcileResult, ServiceError> = async {
        let t = Instant::now();
        let existing = zone::find_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        let created = existing.is_none();
        let default_ttl = if let Some(zone) = &existing {
            authorize_import(caller, mode, zone)?;
            zone.default_ttl
        } else if request.create {
            caller.authorize_action(Action::ZoneCreate)?;
            for action in import_actions(mode) {
                caller.authorize_all_whole_zones(*action)?;
            }
            cx.config().dns.zone_defaults.ttl
        } else {
            return Err(ServiceError::zone_not_found(zone_name));
        };
        timings.load_zone_ms = elapsed_ms(t);

        let t = Instant::now();
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

        // Normalize parsed records and drop duplicates within the file by identity.
        let t = Instant::now();
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
                Err(e) => {
                    errors.push(format!("{}: {}", record.owner_fqdn, e));
                    continue;
                }
            };
            let stored_name = match normalize_record_owner_name(&record.owner_fqdn, &zone.name) {
                Ok(stored_name) => stored_name,
                Err(e) => {
                    errors.push(format!("{}: {}", record.owner_fqdn, e));
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

        timings.normalize_ms = elapsed_ms(t);
        let parsed_count = desired.len();

        // Append checks only matching owners; replace/upsert need all rows to find deletions.
        let t = Instant::now();
        let existing_records = if created {
            Ok(Vec::new())
        } else {
            match mode {
                ImportMode::Append => {
                    let mut names: Vec<OwnerName> =
                        desired.iter().map(|d| d.data.name.clone()).collect();
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
        .map_err(|e| {
            log::error!("Failed to load zone records: {}", e);
            ServiceError::internal_with_source("failed to import zone file", e)
        })?;
        timings.load_existing_ms = elapsed_ms(t);

        let t = Instant::now();
        let plan = ImportPlan::compute(mode, &existing_records, &desired);
        timings.reconcile_ms = elapsed_ms(t);

        let mut all_dels = plan.dels.clone();
        all_dels.extend_from_slice(&plan.ttl_dels);
        let mut to_insert: Vec<Record> = plan
            .adds
            .iter()
            .map(|add| Record {
                id: RecordId::UNWRITTEN,
                name: add.data.name.clone(),
                record_type: add.data.record_type,
                value: add.data.value.clone(),
                ttl: add.data.ttl,
                priority: add.data.priority,
                zone_id: zone.id,
                created_at: Utc::now(),
            })
            .collect();

        // Validate additions without writes, indexing simulated records by owner for conflict checks.
        let t = Instant::now();
        let del_ids: HashSet<RecordId> = all_dels.iter().map(|record| record.id).collect();
        let mut simulated_by_name: HashMap<OwnerName, Vec<Record>> =
            HashMap::with_capacity(existing_records.len());
        for record in &existing_records {
            if !del_ids.contains(&record.id) {
                simulated_by_name
                    .entry(record.name.clone())
                    .or_default()
                    .push(record.clone());
            }
        }
        for (add, candidate) in plan.adds.iter().zip(&to_insert) {
            let records_at_name = simulated_by_name
                .entry(add.data.name.clone())
                .or_default();
            match validate_record_constraints(
                records_at_name,
                &add.data.name,
                &add.data.record_type,
                &add.data.value,
                add.data.ttl,
                add.data.priority,
                None,
            ) {
                Ok(()) => records_at_name.push(candidate.clone()),
                Err(e) => errors.push(format!("{}: {}", add.source_name, e)),
            }
        }
        if errors.is_empty()
            && let Err(error) =
                zone::validate_record_changes_tx(&mut tx, &zone, &all_dels, &to_insert).await
        {
            if error.code().is_internal() {
                return Err(error);
            }
            errors.push(error.to_string());
        }
        timings.validate_ms = elapsed_ms(t);

        let summary = ImportZoneSummaryResponse {
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
            RecordDiffResponse::default()
        };

        let will_apply = errors.is_empty() && !run.is_dry_run();
        let has_changes = !plan.dels.is_empty() || !plan.adds.is_empty() || !plan.ttl_dels.is_empty();

        let new_serial = if has_changes && errors.is_empty() {
            generate_serial(Some(zone.serial))
        } else {
            zone.serial
        };
        if will_apply && created {
            zone = zone::create_tx(&mut tx, zone).await?;
            for record in &mut to_insert {
                record.zone_id = zone.id;
            }
            zone::save_version_tx(&mut tx, &zone, zone.serial, caller.change_attribution()).await?;
        }
        if will_apply && has_changes {
            let t = Instant::now();
            super::delete_with_changes_tx(&mut tx, zone.id, new_serial, &all_dels).await?;
            super::create_with_changes_tx(&mut tx, zone.id, new_serial, &to_insert).await?;
            timings.db_write_ms = elapsed_ms(t);

            let t = Instant::now();
            dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
            zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_attribution()).await?;
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

        Ok(ReconcileResult {
            response,
            zone_name: zone.name,
            changed: will_apply && has_changes,
            created: will_apply && created,
        })
    }
    .await;

    let ReconcileResult {
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

    let t = Instant::now();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    /// Verify that `normalize_zone_names` canonicalizes and drops repeats in request order.
    #[test]
    fn normalize_zone_names_canonicalizes_and_drops_repeats() {
        let names =
            ["Example.COM.", "example.net", " example.com", "example.net"].map(str::to_string);

        let zones = normalize_zone_names(&names).unwrap();

        assert_eq!(
            zones,
            vec![
                ZoneName::parse("example.com").unwrap(),
                ZoneName::parse("example.net").unwrap(),
            ]
        );
    }

    /// Verify that `normalize_zone_names` rejects an empty list and a name no zone can carry.
    #[test]
    fn normalize_zone_names_rejects_empty_list_and_bad_name() {
        let empty = normalize_zone_names(&[]).unwrap_err();
        assert_eq!(empty.code(), ErrorCode::InvalidInput);

        let root = normalize_zone_names(&["example.com".to_string(), ".".to_string()]).unwrap_err();
        assert_eq!(root.code(), ErrorCode::InvalidZoneField);
    }
}
