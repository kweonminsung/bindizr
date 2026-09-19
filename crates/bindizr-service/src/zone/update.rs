use bindizr_core::dns::{CATALOG_ZONE_NAME, name::OwnerName};
use bindizr_db::repository::LockLevel;

use super::ZoneService;
use crate::{
    authorization::Caller,
    dnssec::DnssecService,
    error::{ErrorCode, ServiceError},
    model::{
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    record::validate_record_name_in_zone,
    repository::RepositoryService,
    serial::generate_serial,
    types::{CreateZoneRequest, GetZoneResponse, UpdateZoneRequest, ZoneWriteResponse},
    zone::{
        validation::{ResolvedSoaTimers, normalize_create_zone_request, normalize_soa_timers},
        version::ChangeSubject,
    },
};

/// Outcome of the transactional part of a zone update.
struct AppliedZoneUpdate {
    zone: Zone,
    /// Whether the update changed what the catalog publishes: its members are
    /// the enabled zones, listed by name.
    catalog_changed: bool,
    new_serial: i32,
}

/// DEL(old)+ADD(new) apex SOA changes for an in-place zone row update, so IXFR
/// consumers replay the SOA transition.
pub(crate) fn soa_replacement_changes(
    old_zone: &Zone,
    new_zone: &Zone,
    new_serial: i32,
) -> Result<Vec<ZoneChange>, ServiceError> {
    let change = |operation: ChangeOperation, zone: &Zone| -> Result<ZoneChange, ServiceError> {
        Ok(ZoneChange {
            zone_id: old_zone.id,
            serial: new_serial,
            operation,
            record_name: OwnerName::apex(),
            record_type: JournalRecordType::Soa,
            record_value: Some(
                zone.soa_presentation_rdata()
                    .map_err(ServiceError::invalid_zone_field)?,
            ),
            record_rdata: None,
            record_ttl: zone.default_ttl,
            record_priority: None,
            derived: false,
        })
    };

    Ok(vec![
        change(ChangeOperation::Del, old_zone)?,
        change(ChangeOperation::Add, new_zone)?,
    ])
}

impl ZoneService {
    /// Omitted fields keep the stored zone's value; the merge runs inside the
    /// transaction, against the locked row.
    pub async fn update(
        caller: &Caller,
        zone_name: &str,
        request: &UpdateZoneRequest,
    ) -> Result<ZoneWriteResponse, ServiceError> {
        caller.authorize_global("update zones")?;
        // The serial is a system-managed version counter, never set on update.
        if request.serial.is_some() {
            return Err(ServiceError::invalid_input(
                "serial is managed automatically and cannot be set on update",
            ));
        }
        let updated_zone = Self::update_locked(
            zone_name,
            &caller.change_subject(),
            request.enabled,
            request.dry_run,
            |existing| {
                CreateZoneRequest {
                    dry_run: false,
                    name: request
                        .name
                        .clone()
                        .unwrap_or_else(|| existing.name.to_string()),
                    mname: request
                        .mname
                        .clone()
                        .unwrap_or_else(|| existing.mname.clone()),
                    rname: request
                        .rname
                        .clone()
                        .unwrap_or_else(|| existing.rname.clone()),
                    default_ttl: Some(request.default_ttl.unwrap_or(existing.default_ttl)),
                    serial: None,
                    // Omitted timers fall back to the existing zone in normalize_soa_timers.
                    refresh: request.refresh,
                    retry: request.retry,
                    expire: request.expire,
                    minimum_ttl: request.minimum_ttl,
                    description: request
                        .description
                        .clone()
                        .or_else(|| existing.description.clone()),
                }
            },
        )
        .await?;
        Ok(ZoneWriteResponse {
            applied: !request.dry_run,
            dry_run: request.dry_run,
            zone: GetZoneResponse::from_zone(&updated_zone),
        })
    }

    /// Lock the zone, build the effective request against it, then apply:
    /// bump the serial and record SOA/NS changes for IXFR.
    async fn update_locked(
        zone_name: &str,
        subject: &ChangeSubject,
        enabled: Option<bool>,
        dry_run: bool,
        build: impl FnOnce(&Zone) -> CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        let mut tx = RepositoryService::begin_tx("Failed to update zone").await?;

        let apply_result: Result<AppliedZoneUpdate, ServiceError> = async {
            // Lock the zone row so the serial computed below stays ahead of
            // concurrent record mutations and nsupdate on the same zone.
            let existing_zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let zone_id = existing_zone.id;

            let request = build(&existing_zone);
            let validated = normalize_create_zone_request(&request)?;

            // A longer zone name lengthens every record's wire name, so the
            // records must still fit under it or the zone stops transferring.
            if validated.name != existing_zone.name {
                let records =
                    RepositoryService::list_records_tx(&mut tx, zone_id, LockLevel::None).await?;
                for record in &records {
                    validate_record_name_in_zone(&record.name, &validated.name)?;
                }
            }

            let timers = normalize_soa_timers(
                &request,
                ResolvedSoaTimers {
                    refresh: existing_zone.refresh,
                    retry: existing_zone.retry,
                    expire: existing_zone.expire,
                    minimum_ttl: existing_zone.minimum_ttl,
                },
            )?;

            // Friendly rename-conflict check (unlocked read to avoid ordering
            // deadlocks); renames that race past it hit the UNIQUE(name)
            // backstop, which maps to the same conflict error.
            if validated.name != existing_zone.name {
                match RepositoryService::get_zone_by_name(validated.name.as_str()).await {
                    Ok(Some(zone)) if zone.id != zone_id => {
                        log::error!("Zone with name {} already exists", validated.name);
                        return Err(ServiceError::zone_conflict(format!(
                            "Zone with name '{}' already exists",
                            validated.name
                        )));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("Failed to check existing zone: {}", e);
                        return Err(ServiceError::internal("Failed to update zone"));
                    }
                }
            }

            let new_serial = generate_serial(Some(existing_zone.serial))?;

            let candidate = Zone {
                id: zone_id,
                name: validated.name,
                mname: validated.mname,
                rname: validated.rname,
                default_ttl: validated.ttl,
                serial: new_serial,
                refresh: timers.refresh,
                retry: timers.retry,
                expire: timers.expire,
                minimum_ttl: timers.minimum_ttl,
                dnssec_policy_id: existing_zone.dnssec_policy_id,
                parent_ns_addrs: existing_zone.parent_ns_addrs.clone(),
                enabled: enabled.unwrap_or(existing_zone.enabled),
                description: validated.description,
                created_at: existing_zone.created_at,
            };

            // The change is validated, so a dry run stops here.
            if dry_run {
                return Ok(AppliedZoneUpdate {
                    new_serial: candidate.serial,
                    zone: candidate,
                    catalog_changed: false,
                });
            }

            let updated_zone = RepositoryService::update_zone_tx(&mut tx, candidate)
                .await
                .map_err(|e| {
                    log::error!("Failed to update zone: {}", e);
                    // Keep the conflict mapped from the UNIQUE(name) backstop; it
                    // covers renames that raced past the pre-check above.
                    if e.code == ErrorCode::ZoneConflict {
                        e
                    } else {
                        ServiceError::internal("Failed to update zone")
                    }
                })?;

            // Journal the SOA and signature changes under the zone update's serial,
            // then save the version that future IXFR and rollback reads will use.
            let changes = soa_replacement_changes(&existing_zone, &updated_zone, new_serial)?;

            RepositoryService::create_zone_changes_tx(&mut tx, &changes)
                .await
                .map_err(|e| {
                    log::error!("Failed to create zone changes: {}", e);
                    ServiceError::internal("Failed to create zone change")
                })?;

            DnssecService::sign_zone_tx(&mut tx, &updated_zone, new_serial).await?;
            ZoneService::save_version_tx(&mut tx, &updated_zone, new_serial, subject).await?;

            Ok(AppliedZoneUpdate {
                catalog_changed: existing_zone.name != updated_zone.name
                    || existing_zone.enabled != updated_zone.enabled,
                zone: updated_zone,
                new_serial,
            })
        }
        .await;

        let AppliedZoneUpdate {
            zone: updated_zone,
            catalog_changed,
            new_serial,
        } = RepositoryService::finish_tx(tx, apply_result, "Failed to update zone").await?;

        log::info!(
            "event=zone_update zone={} previous_name={} new_serial={} zone_id={}",
            updated_zone.name,
            zone_name,
            new_serial,
            updated_zone.id
        );

        // Announce the zone's new serial after its data and version have committed.
        if !dry_run
            && let Err(e) =
                crate::notify::send_notify_after_update(Some(updated_zone.name.as_str())).await
        {
            log::warn!(
                "Failed to send NOTIFY for zone {}: {}",
                updated_zone.name,
                e
            );
        }

        // Renaming or toggling a zone also changes the catalog seen by secondaries.
        if !dry_run
            && catalog_changed
            && let Err(e) = crate::notify::send_notify_after_update(Some(CATALOG_ZONE_NAME)).await
        {
            log::warn!("Failed to send NOTIFY for {}: {}", CATALOG_ZONE_NAME, e);
        }

        Ok(updated_zone)
    }
}
