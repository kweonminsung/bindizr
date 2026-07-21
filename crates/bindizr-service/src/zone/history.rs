//! Zone serial history: snapshot listing, point-in-time record reconstruction,
//! and serial-based rollback.

use std::collections::{HashMap, HashSet};

use bindizr_core::dns::name::{soa_mailbox_to_email, to_fqdn};
use chrono::Utc;

use super::{ZoneService, snapshot::save_zone_snapshot_tx, validation::normalize_zone_name};
use crate::{
    RepositoryTx,
    error::ServiceError,
    log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone::Zone,
        zone_change::ZoneChange,
        zone_snapshot::ZoneSnapshot,
    },
    record::{
        canonical_record_value, delete_records_tx, insert_validated_records_tx, load_zone_tx,
        validate_delete_constraints, validate_record_add_constraints_normalized,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{PaginatedResponse, RollbackSummary, RollbackZoneResponse},
};

/// A record as it existed at a past serial, rebuilt from the change history;
/// carries no database id.
#[derive(Debug, Clone)]
pub struct ReconstructedRecord {
    pub name: String,
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}

impl From<Record> for ReconstructedRecord {
    fn from(record: Record) -> Self {
        ReconstructedRecord {
            name: record.name,
            record_type: record.record_type,
            value: record.value,
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

impl From<ReconstructedRecord> for crate::types::SnapshotRecordResponse {
    fn from(record: ReconstructedRecord) -> Self {
        crate::types::SnapshotRecordResponse {
            name: record.name,
            record_type: record.record_type.to_string(),
            value: record.value,
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

/// Hash key identifying a record for set matching: lowercased owner name,
/// type, and the canonical comparison form of the value(+priority).
type MatchKey = (String, String, String);

fn match_key(name: &str, record_type: &RecordType, value: &str, priority: Option<i32>) -> MatchKey {
    (
        name.to_ascii_lowercase(),
        record_type.to_string(),
        canonical_record_value(value, priority, record_type).into_owned(),
    )
}

fn record_match_key(record: &Record) -> MatchKey {
    match_key(
        &record.name,
        &record.record_type,
        &record.value,
        record.priority,
    )
}

/// Reverse-apply the zone's change history in `(target_serial, current_serial]`
/// onto the current record set, yielding the record set at `target_serial`.
/// SOA rows are skipped (SOA state is restored from `zone_soa_history`).
async fn reconstruct_records_at_serial(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
    target_serial: i32,
    current_serial: i32,
) -> Result<Vec<ReconstructedRecord>, ServiceError> {
    let mut state: HashMap<MatchKey, Vec<ReconstructedRecord>> = HashMap::new();
    for record in RepositoryService::get_records_by_zone_id_tx(tx, zone_id).await? {
        state
            .entry(record_match_key(&record))
            .or_default()
            .push(record.into());
    }

    let changes = RepositoryService::get_zone_changes_between_serials_tx(
        tx,
        zone_id,
        target_serial,
        current_serial,
    )
    .await?;

    // Changes arrive ordered by (serial, id) ascending; undo them newest-first.
    for change in changes.iter().rev() {
        if change.record_type == "SOA" {
            continue;
        }
        let record_type: RecordType = match change.record_type.parse() {
            Ok(record_type) => record_type,
            Err(_) => {
                log_warn!(
                    "Skipping zone change with unknown record type '{}' during reconstruction",
                    change.record_type
                );
                continue;
            }
        };
        let key = match_key(
            &change.record_name,
            &record_type,
            &change.record_value,
            change.record_priority,
        );

        match change.operation.as_str() {
            "ADD" => match state.get_mut(&key).and_then(Vec::pop) {
                Some(_) => {}
                // Tolerated: history anomalies (e.g. rows removed outside
                // the change log) must not brick reconstruction.
                None => log_warn!(
                    "No matching record to undo ADD of '{}' {} during reconstruction",
                    change.record_name,
                    change.record_type
                ),
            },
            "DEL" => {
                // The recorded row existed before this serial; restore it.
                state.entry(key).or_default().push(ReconstructedRecord {
                    name: change.record_name.clone(),
                    record_type,
                    value: change.record_value.clone(),
                    ttl: change.record_ttl,
                    priority: change.record_priority,
                });
            }
            other => log_warn!(
                "Skipping zone change with unknown operation '{}' during reconstruction",
                other
            ),
        }
    }

    let mut records: Vec<ReconstructedRecord> = state.into_values().flatten().collect();
    sort_records(&mut records);
    Ok(records)
}

/// Deterministic output order (hash-map iteration order is not).
fn sort_records(records: &mut [ReconstructedRecord]) {
    records.sort_by(|a, b| {
        (&a.name, a.record_type.to_string(), &a.value).cmp(&(
            &b.name,
            b.record_type.to_string(),
            &b.value,
        ))
    });
}

/// Build the zone as it should look after rolling back to `snapshot`: SOA
/// metadata from the snapshot, identity (id/name) and creation time unchanged,
/// serial advanced to `new_serial`.
fn restored_zone_from_snapshot(
    zone: &Zone,
    snapshot: &ZoneSnapshot,
    new_serial: i32,
) -> Result<Zone, ServiceError> {
    let admin_email = soa_mailbox_to_email(&snapshot.admin_email).map_err(|e| {
        ServiceError::internal(format!("Failed to decode snapshot admin email: {}", e))
    })?;

    Ok(Zone {
        id: zone.id,
        name: zone.name.clone(),
        primary_ns: snapshot.primary_ns.clone(),
        admin_email,
        ttl: snapshot.ttl,
        serial: new_serial,
        refresh: snapshot.refresh,
        retry: snapshot.retry,
        expire: snapshot.expire,
        minimum_ttl: snapshot.minimum_ttl,
        created_at: zone.created_at,
    })
}

fn soa_metadata_changed(zone: &Zone, restored: &Zone) -> bool {
    zone.primary_ns != restored.primary_ns
        || zone.admin_email != restored.admin_email
        || zone.ttl != restored.ttl
        || zone.refresh != restored.refresh
        || zone.retry != restored.retry
        || zone.expire != restored.expire
        || zone.minimum_ttl != restored.minimum_ttl
}

impl ZoneService {
    /// List a zone's snapshots (serial history), newest serial first.
    pub async fn list_snapshots(
        zone_name: &str,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> Result<PaginatedResponse<ZoneSnapshot>, ServiceError> {
        let zone = Self::get_by_name(zone_name).await?;

        let total = RepositoryService::count_zone_snapshots(zone.id).await?;
        let effective_limit = limit.unwrap_or(50);
        let items =
            RepositoryService::list_zone_snapshots(zone.id, effective_limit, offset.unwrap_or(0))
                .await?;

        Ok(crate::pagination::paginated_response(
            items,
            Some(effective_limit),
            offset,
            total,
        ))
    }

    /// Fetch the snapshot at `serial` together with the reconstructed record
    /// set at that serial.
    pub async fn get_snapshot(
        zone_name: &str,
        serial: i32,
    ) -> Result<(ZoneSnapshot, Vec<ReconstructedRecord>), ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_tx("Failed to load snapshot").await?;

        let result = async {
            let zone = load_zone_tx(&mut tx, &lookup_name).await?;
            let snapshot =
                RepositoryService::get_zone_snapshot_by_serial_tx(&mut tx, zone.id, serial)
                    .await?
                    .ok_or_else(|| ServiceError::snapshot_not_found(&zone.name, serial))?;

            let records = if serial == zone.serial {
                let mut records: Vec<ReconstructedRecord> =
                    RepositoryService::get_records_by_zone_id_tx(&mut tx, zone.id)
                        .await?
                        .into_iter()
                        .map(ReconstructedRecord::from)
                        .collect();
                sort_records(&mut records);
                records
            } else {
                reconstruct_records_at_serial(&mut tx, zone.id, serial, zone.serial).await?
            };

            Ok::<_, ServiceError>((snapshot, records))
        }
        .await;

        RepositoryService::finish_tx(tx, result, "Failed to load snapshot").await
    }

    /// Roll a zone back to the state captured at `target_serial`. The record
    /// set and SOA metadata return to that serial's state while the zone's
    /// serial advances to a new value (serials never go backward). The zone
    /// name is not part of a snapshot and is never restored.
    pub async fn rollback(
        zone_name: &str,
        target_serial: i32,
        dry_run: bool,
    ) -> Result<RollbackZoneResponse, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_tx("Failed to roll back zone").await?;

        let apply_result = async {
            let zone = load_zone_tx(&mut tx, &lookup_name).await?;

            if target_serial < 1 || target_serial >= zone.serial {
                return Err(ServiceError::invalid_input(format!(
                    "target serial {} must be less than the current serial {}",
                    target_serial, zone.serial
                )));
            }
            let snapshot =
                RepositoryService::get_zone_snapshot_by_serial_tx(&mut tx, zone.id, target_serial)
                    .await?
                    .ok_or_else(|| ServiceError::snapshot_not_found(&zone.name, target_serial))?;

            let new_serial = generate_serial(Some(zone.serial));
            let restored_zone = restored_zone_from_snapshot(&zone, &snapshot, new_serial)?;
            let soa_changed = soa_metadata_changed(&zone, &restored_zone);

            let current_records =
                RepositoryService::get_records_by_zone_id_tx(&mut tx, zone.id).await?;
            let target_records =
                reconstruct_records_at_serial(&mut tx, zone.id, target_serial, zone.serial).await?;

            // Diff current vs target, import-Replace style. Protection is
            // evaluated against the restored zone so the restored primary_ns's
            // apex NS is kept and the newer one becomes deletable.
            let mut target_by_key: HashMap<MatchKey, Vec<ReconstructedRecord>> = HashMap::new();
            for target in target_records {
                let key = match_key(
                    &target.name,
                    &target.record_type,
                    &target.value,
                    target.priority,
                );
                target_by_key.entry(key).or_default().push(target);
            }

            let mut dels: Vec<Record> = Vec::new();
            let mut unchanged = 0usize;
            let mut to_add: Vec<ReconstructedRecord> = Vec::new();

            for record in &current_records {
                let key = record_match_key(record);
                match target_by_key.get_mut(&key).and_then(Vec::pop) {
                    Some(target) => {
                        // TTL-only difference: replace the row (DEL + ADD).
                        let current_ttl = record.ttl.unwrap_or(restored_zone.ttl);
                        let target_ttl = target.ttl.unwrap_or(restored_zone.ttl);
                        if current_ttl != target_ttl
                            && validate_delete_constraints(
                                &restored_zone,
                                std::slice::from_ref(record),
                            )
                            .is_ok()
                        {
                            dels.push(record.clone());
                            to_add.push(target);
                        } else {
                            unchanged += 1;
                        }
                    }
                    None => {
                        if validate_delete_constraints(&restored_zone, std::slice::from_ref(record))
                            .is_ok()
                        {
                            dels.push(record.clone());
                        } else {
                            // Protected rows (SOA / restored primary NS) stay.
                            unchanged += 1;
                        }
                    }
                }
            }
            to_add.extend(target_by_key.into_values().flatten());

            // Defensive apex-NS guarantee (mirrors zone update): the restored
            // primary_ns must keep a matching apex NS record.
            let restored_ns_fqdn = to_fqdn(&restored_zone.primary_ns).to_ascii_lowercase();
            let is_restored_apex_ns = |record_type: &RecordType, name: &str, value: &str| {
                *record_type == RecordType::NS
                    && name == "@"
                    && to_fqdn(value).to_ascii_lowercase() == restored_ns_fqdn
            };
            let deleted_ids: HashSet<i32> = dels.iter().map(|del| del.id).collect();
            let has_primary_ns = current_records
                .iter()
                .filter(|record| !deleted_ids.contains(&record.id))
                .any(|record| {
                    is_restored_apex_ns(&record.record_type, &record.name, &record.value)
                })
                || to_add.iter().any(|record| {
                    is_restored_apex_ns(&record.record_type, &record.name, &record.value)
                });
            if !has_primary_ns {
                to_add.push(ReconstructedRecord {
                    name: "@".to_string(),
                    record_type: RecordType::NS,
                    value: restored_zone.primary_ns.clone(),
                    ttl: Some(restored_zone.ttl),
                    priority: None,
                });
            }

            // Validate the adds in-memory against the post-delete record set
            // (mirrors the import reconcile).
            let mut records_by_name: HashMap<String, Vec<Record>> = HashMap::new();
            for record in &current_records {
                if deleted_ids.contains(&record.id) {
                    continue;
                }
                records_by_name
                    .entry(record.name.to_ascii_lowercase())
                    .or_default()
                    .push(record.clone());
            }
            let mut to_insert: Vec<Record> = Vec::with_capacity(to_add.len());
            for target in &to_add {
                let same_name = records_by_name
                    .entry(target.name.to_ascii_lowercase())
                    .or_default();
                validate_record_add_constraints_normalized(
                    same_name,
                    &target.name,
                    &target.name,
                    &target.record_type,
                    &target.value,
                    target.priority,
                    None,
                )?;
                let record = Record {
                    id: 0,
                    name: target.name.clone(),
                    record_type: target.record_type.clone(),
                    value: target.value.clone(),
                    ttl: target.ttl,
                    priority: target.priority,
                    zone_id: zone.id,
                    created_at: Utc::now(),
                };
                same_name.push(record.clone());
                to_insert.push(record);
            }

            let summary = RollbackSummary {
                records_added: to_insert.len(),
                records_deleted: dels.len(),
                records_unchanged: unchanged,
                soa_changed,
            };

            if dry_run {
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

            RepositoryService::update_zone_tx(&mut tx, restored_zone.clone()).await?;

            if soa_changed {
                let soa_rdata = |zone: &Zone| -> Result<String, ServiceError> {
                    zone.soa_rdata()
                        .map_err(|e| ServiceError::invalid_zone(e.to_string()))
                };
                let changes = vec![
                    ZoneChange {
                        id: 0,
                        zone_id: zone.id,
                        serial: new_serial,
                        operation: "DEL".to_string(),
                        record_name: "@".to_string(),
                        record_type: "SOA".to_string(),
                        record_value: soa_rdata(&zone)?,
                        record_ttl: Some(zone.ttl),
                        record_priority: None,
                    },
                    ZoneChange {
                        id: 0,
                        zone_id: zone.id,
                        serial: new_serial,
                        operation: "ADD".to_string(),
                        record_name: "@".to_string(),
                        record_type: "SOA".to_string(),
                        record_value: soa_rdata(&restored_zone)?,
                        record_ttl: Some(restored_zone.ttl),
                        record_priority: None,
                    },
                ];
                RepositoryService::create_zone_changes_tx(&mut tx, &changes).await?;
            }

            delete_records_tx(&mut tx, zone.id, new_serial, &dels).await?;
            insert_validated_records_tx(&mut tx, zone.id, new_serial, &to_insert).await?;
            save_zone_snapshot_tx(&mut tx, &restored_zone, new_serial).await?;

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
            RepositoryService::finish_tx(tx, apply_result, "Failed to roll back zone").await?;

        if applied {
            log_info!(
                "event=zone_rollback zone={} target_serial={} new_serial={} added={} deleted={}",
                zone_name,
                response.target_serial,
                response.new_serial,
                response.summary.records_added,
                response.summary.records_deleted
            );
            if let Err(e) = crate::notify::send_notify_after_update(Some(&zone_name)).await {
                log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
            }
        }

        Ok(response)
    }
}
