//! Zone serial history: version listing, rewinding the records to a serial,
//! and serial-based rollback.

mod rewind;

use std::collections::{HashMap, HashSet};

use bindizr_core::{
    dns::{
        Serial,
        name::{OwnerName, ZoneName},
        record::SoaMailbox,
    },
    model::{record::RecordId, role_grant::Action, zone_version::VersionFilter},
};
use bindizr_db::LockLevel;
use chrono::Utc;
use rewind::{list_records_at_serial_tx, rewind_records_to_serial_tx};

use super::{diff::build_record_diff, update::soa_replacement_changes};
use crate::{
    Context, Transaction,
    authorization::Caller,
    dnssec,
    error::ServiceError,
    model::{
        record::{Record, RecordData, RecordKey},
        zone::Zone,
    },
    pagination::{build_paginated_response, normalize_page_limit},
    record::{self, validate_record_add_constraints_normalized, validate_record_name_in_zone},
    serial::{generate_serial, validate_stored_serial},
    transaction,
    types::{
        PaginatedResponse, RollbackSummary, RollbackZoneResponse, Run, VersionDetailResponse,
        VersionDiffResponse, VersionRecordResponse, ZoneVersionResponse,
    },
};

/// A serial is diffable only if it is the current serial or has a version.
async fn validate_serial_diffable_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    serial: Serial,
) -> Result<(), ServiceError> {
    if serial == zone.serial {
        return Ok(());
    }
    bindizr_db::zone_version::get_by_serial_tx(tx, zone.id, serial, LockLevel::Unlocked)
        .await?
        .ok_or_else(|| ServiceError::version_not_found(zone.name.as_str(), serial))?;
    Ok(())
}

/// List the versions `filter` covers, newest serial first.
pub async fn list_versions(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    limit: Option<u32>,
    offset: Option<u64>,
    filter: VersionFilter,
) -> Result<PaginatedResponse<ZoneVersionResponse>, ServiceError> {
    let zone = super::get_by_name(cx, caller, zone_name).await?;
    caller.authorize_zone_action(Action::ZoneRead, &zone)?;

    let total = bindizr_db::zone_version::count_by_filter(cx.db(), zone.id, filter).await?;
    let effective_limit = normalize_page_limit(limit)?;
    let versions = bindizr_db::zone_version::list_by_filter(
        cx.db(),
        zone.id,
        filter,
        effective_limit,
        offset.unwrap_or(0),
    )
    .await?;
    let items = versions
        .iter()
        .map(ZoneVersionResponse::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(build_paginated_response(
        items,
        Some(effective_limit),
        offset,
        total,
    ))
}

/// Fetch the version at `serial` together with the records rewound to it.
pub async fn get_version(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    serial: Serial,
) -> Result<VersionDetailResponse, ServiceError> {
    let serial = validate_stored_serial(serial)?;
    let mut tx = transaction::begin_read_tx(cx, "failed to load version").await?;

    let result = async {
        let zone = super::get_by_name_tx(&mut tx, caller, zone_name, LockLevel::Shared).await?;
        let read = caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_whole_zone_read(&zone)?;
        let version = bindizr_db::zone_version::get_by_serial_tx(
            &mut tx,
            zone.id,
            serial,
            LockLevel::Unlocked,
        )
        .await?
        .ok_or_else(|| ServiceError::version_not_found(zone.name.as_str(), serial))?;

        let records = read.readable_records(
            list_records_at_serial_tx(&mut tx, zone.id, serial, zone.serial).await?,
        );

        Ok::<_, ServiceError>((zone, version, records))
    }
    .await;

    let (zone, version, records) =
        transaction::finish_tx(tx, result, "failed to load version").await?;
    Ok(VersionDetailResponse {
        version: ZoneVersionResponse::try_from(&version)?,
        records: records
            .as_slice()
            .iter()
            .map(|record| VersionRecordResponse::from_record_and_zone_name(record, &zone.name))
            .collect(),
    })
}

/// Compute the record-level difference between two of a zone's serials;
/// `to_serial` defaults to the current one. Each serial must be the
/// current one or an existing version.
pub async fn diff_versions(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    from_serial: Serial,
    to_serial: Option<Serial>,
) -> Result<VersionDiffResponse, ServiceError> {
    let from = validate_stored_serial(from_serial)?;
    let to = to_serial.map(validate_stored_serial).transpose()?;
    let mut tx = transaction::begin_read_tx(cx, "failed to diff versions").await?;

    let result = async {
        let zone = super::get_by_name_tx(&mut tx, caller, zone_name, LockLevel::Shared).await?;
        let read = caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_whole_zone_read(&zone)?;
        let to = to.unwrap_or(zone.serial);

        validate_serial_diffable_tx(&mut tx, &zone, from).await?;
        validate_serial_diffable_tx(&mut tx, &zone, to).await?;

        let from_records = list_records_at_serial_tx(&mut tx, zone.id, from, zone.serial).await?;
        let to_records = list_records_at_serial_tx(&mut tx, zone.id, to, zone.serial).await?;

        Ok::<_, ServiceError>(VersionDiffResponse {
            from_serial,
            to_serial: to,
            diff: build_record_diff(
                &zone,
                &read.readable_records(from_records),
                &read.readable_records(to_records),
            ),
        })
    }
    .await;

    transaction::finish_tx(tx, result, "failed to diff versions").await
}

/// Restore records and SOA metadata at `target_serial`, advancing to a new serial.
/// Versions exclude the zone name, so rollback preserves it.
pub async fn rollback(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    target_serial: Serial,
    run: Run,
) -> Result<RollbackZoneResponse, ServiceError> {
    let target = validate_stored_serial(target_serial)?;

    let mut tx = transaction::begin_tx(cx, "failed to roll back zone").await?;

    let apply_result = async {
        let zone = super::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        // A rollback rewrites the zone's SOA and its records whole, from the
        // stored version it reads.
        caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;
        caller.authorize_whole_zone(Action::RecordRead, &zone)?;
        caller.authorize_whole_zone(Action::RecordCreate, &zone)?;
        caller.authorize_whole_zone(Action::RecordDelete, &zone)?;

        if target.as_u32() < 1 || target >= zone.serial {
            return Err(ServiceError::invalid_input(format!(
                "target serial {} must be less than the current serial {}",
                target, zone.serial
            )));
        }
        let version = bindizr_db::zone_version::get_by_serial_tx(
            &mut tx,
            zone.id,
            target,
            LockLevel::Unlocked,
        )
        .await?
        .ok_or_else(|| ServiceError::version_not_found(zone.name.as_str(), target))?;

        let new_serial = generate_serial(Some(zone.serial))?;
        // SOA metadata comes back from the version; identity and creation
        // time are not part of one and stay.
        let rname = SoaMailbox::from_encoded(&version.rname)
            .to_email()
            .map_err(|e| {
                ServiceError::internal_with_source(
                    format!("failed to decode version rname: {}", e),
                    e,
                )
            })?;
        let restored_zone = Zone {
            id: zone.id,
            name: zone.name.clone(),
            mname: version.mname.clone(),
            rname,
            default_ttl: version.default_ttl,
            serial: new_serial,
            refresh: version.refresh,
            retry: version.retry,
            expire: version.expire,
            dnssec_policy_id: zone.dnssec_policy_id,
            parent_ns_addrs: zone.parent_ns_addrs.clone(),
            enabled: zone.enabled,
            description: zone.description.clone(),
            minimum_ttl: version.minimum_ttl,
            created_at: zone.created_at,
        };
        let soa_changed = zone.soa_metadata_differs(&restored_zone);

        let current_records =
            bindizr_db::record::list_tx(&mut tx, zone.id, LockLevel::Exclusive).await?;
        let target_records =
            rewind_records_to_serial_tx(&mut tx, zone.id, target, zone.serial).await?;

        // Diff current vs target, import-Replace style.
        let mut target_by_key: HashMap<RecordKey, Vec<RecordData>> = HashMap::new();
        for target in target_records {
            target_by_key
                .entry(target.match_key())
                .or_default()
                .push(target);
        }

        let mut dels: Vec<Record> = Vec::new();
        let mut unchanged = 0usize;
        let mut to_add: Vec<RecordData> = Vec::new();

        for record in &current_records {
            let key = record.match_key();
            match target_by_key.get_mut(&key).and_then(Vec::pop) {
                Some(target) => {
                    // A TTL change is a DEL + ADD pair, which RFC 2181,
                    // Section 5.2 requires: one name and type, one TTL.
                    if record.ttl != target.ttl {
                        dels.push(record.clone());
                        to_add.push(target);
                    } else {
                        unchanged += 1;
                    }
                }
                None => dels.push(record.clone()),
            }
        }
        to_add.extend(target_by_key.into_values().flatten());

        let deleted_ids: HashSet<RecordId> = dels.iter().map(|del| del.id).collect();

        // Validate the adds in-memory against the records left after the deletes
        // (mirrors the import reconcile).
        let mut records_by_name: HashMap<OwnerName, Vec<Record>> = HashMap::new();
        for record in &current_records {
            if deleted_ids.contains(&record.id) {
                continue;
            }
            records_by_name
                .entry(record.name.clone())
                .or_default()
                .push(record.clone());
        }
        let mut to_insert: Vec<Record> = Vec::with_capacity(to_add.len());
        for target in &to_add {
            // The history predates the zone's current name, which may no
            // longer fit the names it restores.
            validate_record_name_in_zone(&target.name, &zone.name)?;
            let records_at_name = records_by_name.entry(target.name.clone()).or_default();
            validate_record_add_constraints_normalized(
                records_at_name,
                &target.name,
                &target.record_type,
                &target.value,
                target.ttl,
                target.priority,
                None,
            )?;
            let record = Record {
                id: RecordId::UNWRITTEN,
                name: target.name.clone(),
                record_type: target.record_type,
                value: target.value.clone(),
                ttl: target.ttl,
                priority: target.priority,
                zone_id: zone.id,
                created_at: Utc::now(),
            };
            records_at_name.push(record.clone());
            to_insert.push(record);
        }

        let summary = RollbackSummary {
            added: to_insert.len() as u64,
            deleted: dels.len() as u64,
            unchanged: unchanged as u64,
            soa_changed,
        };

        // A preview stops after the rewind and validation, before restoring rows.
        if run.is_dry_run() {
            return Ok((
                RollbackZoneResponse {
                    applied: false,
                    dry_run: true,
                    target_serial,
                    new_serial,
                    summary,
                },
                zone.name.clone(),
                false,
            ));
        }

        // Restore metadata and records as a new version in this transaction.
        bindizr_db::zone::update_tx(&mut tx, restored_zone.clone()).await?;

        if soa_changed {
            let changes = soa_replacement_changes(&zone, &restored_zone, new_serial)?;
            bindizr_db::zone_change::create_many_tx(&mut tx, &changes).await?;
        }

        record::delete_with_changes_tx(&mut tx, zone.id, new_serial, &dels).await?;
        record::create_with_changes_tx(&mut tx, zone.id, new_serial, &to_insert).await?;
        // The restored user plane gets fresh signatures; old RRSIGs are
        // never restored (derived journal rows are skipped on rewind).
        dnssec::sign_zone_tx(&mut tx, &restored_zone, new_serial).await?;
        super::save_version_tx(
            &mut tx,
            cx,
            &restored_zone,
            new_serial,
            caller.change_attribution(),
        )
        .await?;

        Ok((
            RollbackZoneResponse {
                applied: true,
                dry_run: false,
                target_serial,
                new_serial,
                summary,
            },
            zone.name.clone(),
            true,
        ))
    }
    .await;

    let (response, zone_name, applied) =
        transaction::finish_tx(tx, apply_result, "failed to roll back zone").await?;

    // Announce only an applied rollback after its new version has committed.
    if applied {
        log::info!(
            "event=zone_rollback zone={} target_serial={} new_serial={} added={} deleted={}",
            zone_name,
            response.target_serial,
            response.new_serial,
            response.summary.added,
            response.summary.deleted
        );
        crate::notify::notify_after_update(cx, &zone_name).await;
    }

    Ok(response)
}
