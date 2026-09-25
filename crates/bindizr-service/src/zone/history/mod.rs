//! Zone serial history: version listing, point-in-time record reconstruction,
//! and serial-based rollback.

mod reconstruction;

use std::collections::{HashMap, HashSet};

use bindizr_core::dns::{name::OwnerName, record::SoaMailbox};
use bindizr_db::repository::LockLevel;
use chrono::Utc;
use reconstruction::{list_records_at_serial_tx, reconstruct_records_at_serial_tx};

use super::{
    ZoneService, diff::build_record_diff, update::soa_replacement_changes,
    validation::normalize_zone_name,
};
use crate::{
    RepositoryTx,
    authorization::Caller,
    dnssec::DnssecService,
    error::ServiceError,
    model::{
        record::{Record, RecordData, RecordKey},
        zone::Zone,
    },
    record::{
        RecordService, validate_record_add_constraints_normalized, validate_record_name_in_zone,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{
        PaginatedResponse, RollbackSummary, RollbackZoneResponse, VersionDetailResponse,
        VersionDiffResponse, VersionRecordResponse, ZoneVersionResponse, normalize_page_limit,
    },
};

impl ZoneService {
    /// A serial is diffable only if it is the current serial or has a version.
    async fn validate_serial_diffable_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        serial: i32,
    ) -> Result<(), ServiceError> {
        if serial == zone.serial {
            return Ok(());
        }
        RepositoryService::get_zone_version_by_serial_tx(tx, zone.id, serial, LockLevel::None)
            .await?
            .ok_or_else(|| ServiceError::version_not_found(zone.name.as_str(), serial))?;
        Ok(())
    }

    /// List a zone's versions (serial history), newest serial first. Unless
    /// `include_signer_serials`, signer-only serials (DNSSEC re-signs,
    /// rollovers) are skipped —
    /// they hold nothing rollback could restore. Visibility is checked on the
    /// row whose id the queries use, so a same-name recreation cannot swap
    /// the zone in.
    pub async fn list_versions(
        caller: &Caller,
        zone_name: &str,
        limit: Option<u32>,
        offset: Option<u64>,
        include_signer_serials: bool,
    ) -> Result<PaginatedResponse<ZoneVersionResponse>, ServiceError> {
        let zone = Self::get_by_name(caller, zone_name).await?;

        let total =
            RepositoryService::count_zone_versions(zone.id, !include_signer_serials).await?;
        let effective_limit = normalize_page_limit(limit)?;
        let versions = RepositoryService::list_zone_versions(
            zone.id,
            !include_signer_serials,
            effective_limit,
            offset.unwrap_or(0),
        )
        .await?;
        let items = versions
            .iter()
            .map(ZoneVersionResponse::from_version)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(PaginatedResponse::from_page(
            items,
            Some(effective_limit),
            offset,
            total,
        ))
    }

    /// Fetch the version at `serial` together with the reconstructed records
    /// at that serial. Visibility is checked on the row this tx locked, so
    /// a same-name recreation cannot swap the zone in.
    pub async fn get_version(
        caller: &Caller,
        zone_name: &str,
        serial: i32,
    ) -> Result<VersionDetailResponse, ServiceError> {
        let mut tx = RepositoryService::begin_read_tx("Failed to load version").await?;

        let result = async {
            let zone =
                ZoneService::get_visible_by_name_tx(&mut tx, caller, zone_name, LockLevel::Shared)
                    .await?;
            caller.authorize_zone_unrestricted(&zone)?;
            let version = RepositoryService::get_zone_version_by_serial_tx(
                &mut tx,
                zone.id,
                serial,
                LockLevel::None,
            )
            .await?
            .ok_or_else(|| ServiceError::version_not_found(zone.name.as_str(), serial))?;

            let records = list_records_at_serial_tx(&mut tx, zone.id, serial, zone.serial).await?;

            Ok::<_, ServiceError>((zone, version, records))
        }
        .await;

        let (zone, version, records) =
            RepositoryService::finish_tx(tx, result, "Failed to load version").await?;
        Ok(VersionDetailResponse {
            version: ZoneVersionResponse::from_version(&version)?,
            records: records
                .iter()
                .map(|record| VersionRecordResponse::from_record_and_zone_name(record, &zone.name))
                .collect(),
        })
    }

    /// Compute the record-level difference between two of a zone's serials.
    /// `to_serial` defaults to the zone's current serial when `None`. Each
    /// serial must be the current one or an existing version. Visibility is
    /// checked on the row this tx locked, so a same-name recreation cannot
    /// swap the zone in.
    pub async fn diff_versions(
        caller: &Caller,
        zone_name: &str,
        from_serial: i32,
        to_serial: Option<i32>,
    ) -> Result<VersionDiffResponse, ServiceError> {
        let mut tx = RepositoryService::begin_read_tx("Failed to diff versions").await?;

        let result = async {
            let zone =
                ZoneService::get_visible_by_name_tx(&mut tx, caller, zone_name, LockLevel::Shared)
                    .await?;
            caller.authorize_zone_unrestricted(&zone)?;
            let to_serial = to_serial.unwrap_or(zone.serial);

            Self::validate_serial_diffable_tx(&mut tx, &zone, from_serial).await?;
            Self::validate_serial_diffable_tx(&mut tx, &zone, to_serial).await?;

            let from_records =
                list_records_at_serial_tx(&mut tx, zone.id, from_serial, zone.serial).await?;
            let to_records =
                list_records_at_serial_tx(&mut tx, zone.id, to_serial, zone.serial).await?;

            Ok::<_, ServiceError>(VersionDiffResponse {
                from_serial,
                to_serial,
                diff: build_record_diff(&zone, &from_records, &to_records),
            })
        }
        .await;

        RepositoryService::finish_tx(tx, result, "Failed to diff versions").await
    }

    /// Roll a zone back to the state captured at `target_serial`. The records
    /// and SOA metadata return to that serial's state while the zone's
    /// serial advances to a new value (serials never go backward). The zone
    /// name is not part of a version and is never restored.
    pub async fn rollback(
        caller: &Caller,
        zone_name: &str,
        target_serial: i32,
        dry_run: bool,
    ) -> Result<RollbackZoneResponse, ServiceError> {
        caller.authorize_global("roll back zones")?;

        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_tx("Failed to roll back zone").await?;

        let apply_result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, lookup_name.as_str(), LockLevel::Exclusive)
                    .await?;

            if target_serial < 1 || target_serial >= zone.serial {
                return Err(ServiceError::invalid_input(format!(
                    "target serial {} must be less than the current serial {}",
                    target_serial, zone.serial
                )));
            }
            let version = RepositoryService::get_zone_version_by_serial_tx(
                &mut tx,
                zone.id,
                target_serial,
                LockLevel::None,
            )
            .await?
            .ok_or_else(|| ServiceError::version_not_found(zone.name.as_str(), target_serial))?;

            let new_serial = generate_serial(Some(zone.serial))?;
            // SOA metadata comes back from the version; identity and creation
            // time are not part of one and stay.
            let rname = SoaMailbox::from_encoded(&version.rname)
                .to_email()
                .map_err(|e| {
                    ServiceError::internal(format!("Failed to decode version rname: {}", e))
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
                RepositoryService::list_records_tx(&mut tx, zone.id, LockLevel::Exclusive).await?;
            let target_records =
                reconstruct_records_at_serial_tx(&mut tx, zone.id, target_serial, zone.serial)
                    .await?;

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

            let deleted_ids: HashSet<i32> = dels.iter().map(|del| del.id).collect();

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
                    id: 0,
                    name: target.name.clone(),
                    record_type: target.record_type.clone(),
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
                records_added: to_insert.len(),
                records_deleted: dels.len(),
                records_unchanged: unchanged,
                soa_changed,
            };

            // A preview stops after reconstruction and validation, before restoring rows.
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

            // Restore metadata and records as a new version in this transaction.
            RepositoryService::update_zone_tx(&mut tx, restored_zone.clone()).await?;

            if soa_changed {
                let changes = soa_replacement_changes(&zone, &restored_zone, new_serial)?;
                RepositoryService::create_zone_changes_tx(&mut tx, &changes).await?;
            }

            RecordService::delete_with_changes_tx(&mut tx, zone.id, new_serial, &dels).await?;
            RecordService::create_with_changes_tx(&mut tx, zone.id, new_serial, &to_insert).await?;
            // The restored user plane gets fresh signatures; old RRSIGs are
            // never restored (derived journal rows are skipped on reconstruction).
            DnssecService::sign_zone_tx(&mut tx, &restored_zone, new_serial).await?;
            ZoneService::save_version_tx(
                &mut tx,
                &restored_zone,
                new_serial,
                &caller.change_subject(),
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
            RepositoryService::finish_tx(tx, apply_result, "Failed to roll back zone").await?;

        // Announce only an applied rollback after its new version has committed.
        if applied {
            log::info!(
                "event=zone_rollback zone={} target_serial={} new_serial={} added={} deleted={}",
                zone_name,
                response.target_serial,
                response.new_serial,
                response.summary.records_added,
                response.summary.records_deleted
            );
            if let Err(e) = crate::notify::send_notify_after_update(Some(zone_name.as_str())).await
            {
                log::warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
            }
        }

        Ok(response)
    }
}
