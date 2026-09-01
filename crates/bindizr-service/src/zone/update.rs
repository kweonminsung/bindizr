use bindizr_core::dns::{
    CATALOG_ZONE_NAME,
    name::{OwnerName, ZoneName},
};
use bindizr_db::repository::LockLevel;

use super::ZoneService;
use crate::{
    authorization::Caller,
    dnssec::DnssecService,
    error::{ErrorCode, ServiceError},
    log_error, log_info, log_warn,
    model::{
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    record::RecordService,
    repository::RepositoryService,
    serial::generate_serial,
    types::{CreateZoneRequest, UpdateZonePatch},
    zone::validation::{ResolvedSoaTimers, resolve_soa_timers, validate_create_zone_request},
};

/// Outcome of the transactional part of a zone update.
struct AppliedZoneUpdate {
    zone: Zone,
    previous_name: ZoneName,
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
    /// Full replacement (HTTP PUT): the request supplies every field.
    pub async fn update(
        caller: &Caller,
        zone_name: &str,
        request: &CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        caller.require_global("update zones")?;
        reject_serial(request.serial)?;
        Self::update_locked(zone_name, |_existing| CreateZoneRequest {
            name: request.name.clone(),
            mname: request.mname.clone(),
            rname: request.rname.clone(),
            default_ttl: request.default_ttl,
            serial: None,
            refresh: request.refresh,
            retry: request.retry,
            expire: request.expire,
            minimum_ttl: request.minimum_ttl,
        })
        .await
    }

    /// Partial update (CLI): omitted fields keep the stored zone's value. The
    /// merge runs inside the transaction, against the locked row.
    pub async fn patch(
        caller: &Caller,
        zone_name: &str,
        patch: &UpdateZonePatch,
    ) -> Result<Zone, ServiceError> {
        caller.require_global("update zones")?;
        reject_serial(patch.serial)?;
        Self::update_locked(zone_name, |existing| CreateZoneRequest {
            name: patch
                .new_name
                .clone()
                .unwrap_or_else(|| existing.name.to_string()),
            mname: patch
                .mname
                .clone()
                .unwrap_or_else(|| existing.mname.clone()),
            rname: patch
                .rname
                .clone()
                .unwrap_or_else(|| existing.rname.clone()),
            default_ttl: patch.default_ttl.unwrap_or(existing.default_ttl),
            serial: None,
            // Omitted timers fall back to the existing zone in resolve_soa_timers.
            refresh: patch.refresh,
            retry: patch.retry,
            expire: patch.expire,
            minimum_ttl: patch.minimum_ttl,
        })
        .await
    }

    /// Lock the zone, build the effective request against it, then apply:
    /// bump the serial and record SOA/NS changes for IXFR.
    async fn update_locked(
        zone_name: &str,
        build: impl FnOnce(&Zone) -> CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        let mut tx = RepositoryService::begin_tx("Failed to update zone").await?;

        let apply_result: Result<AppliedZoneUpdate, ServiceError> = async {
            // Lock the zone row so the serial computed below stays ahead of
            // concurrent record mutations and nsupdate on the same zone.
            let existing_zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let zone_id = existing_zone.id;

            // Merge against the locked row, then validate.
            let request = build(&existing_zone);
            let validated = validate_create_zone_request(&request)?;

            // Preserve the zone's current SOA timers when the request omits them.
            let timers = resolve_soa_timers(
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
                        log_error!("Zone with name {} already exists", validated.name);
                        return Err(ServiceError::zone_conflict(format!(
                            "Zone with name '{}' already exists",
                            validated.name
                        )));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log_error!("Failed to check existing zone: {}", e);
                        return Err(ServiceError::internal("Failed to update zone"));
                    }
                }
            }

            let new_serial = generate_serial(Some(existing_zone.serial))?;

            let updated_zone = RepositoryService::update_zone_tx(
                &mut tx,
                Zone {
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
                    dnssec_denial: existing_zone.dnssec_denial,
                    dnssec_signature_validity_days: existing_zone.dnssec_signature_validity_days,
                    dnssec_signature_refresh_days: existing_zone.dnssec_signature_refresh_days,
                    dnssec_zsk_lifetime_days: existing_zone.dnssec_zsk_lifetime_days,
                    created_at: existing_zone.created_at,
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to update zone: {}", e);
                // Keep the conflict mapped from the UNIQUE(name) backstop; it
                // covers renames that raced past the pre-check above.
                if e.code == ErrorCode::ZoneConflict {
                    e
                } else {
                    ServiceError::internal("Failed to update zone")
                }
            })?;

            // A rename / mname change must keep an apex NS matching the new
            // mname; only apex rows can satisfy that, so load just those.
            let apex_records = RepositoryService::list_records_by_name_tx(
                &mut tx,
                zone_id,
                &OwnerName::apex(),
                LockLevel::Exclusive,
            )
            .await
            .map_err(|e| {
                log_error!("Failed to fetch apex records: {}", e);
                ServiceError::internal("Failed to update zone")
            })?;
            let has_mname = apex_records
                .iter()
                .any(|r| updated_zone.is_mname(&r.record_type, &r.name, &r.value));

            if !has_mname {
                let mname_record = updated_zone.mname_record(
                    updated_zone.apex_ns_rrset_ttl(
                        apex_records
                            .iter()
                            .map(|r| (&r.record_type, &r.name, r.ttl)),
                    ),
                );

                RecordService::insert_records_with_changes_tx(
                    &mut tx,
                    zone_id,
                    new_serial,
                    &[mname_record],
                )
                .await
                .map_err(|e| {
                    log_error!("Failed to create mname NS record during update: {}", e);
                    ServiceError::internal("Failed to keep mname NS consistency")
                })?;
            }

            let changes = soa_replacement_changes(&existing_zone, &updated_zone, new_serial)?;

            RepositoryService::create_zone_journal_tx(&mut tx, &changes)
                .await
                .map_err(|e| {
                    log_error!("Failed to create zone changes: {}", e);
                    ServiceError::internal("Failed to create zone change")
                })?;

            DnssecService::sign_zone_tx(&mut tx, &updated_zone, new_serial).await?;
            ZoneService::save_version_tx(&mut tx, &updated_zone, new_serial).await?;

            Ok(AppliedZoneUpdate {
                zone: updated_zone,
                previous_name: existing_zone.name,
                new_serial,
            })
        }
        .await;

        let AppliedZoneUpdate {
            zone: updated_zone,
            previous_name,
            new_serial,
        } = RepositoryService::finish_tx(tx, apply_result, "Failed to update zone").await?;

        log_info!(
            "event=zone_update zone={} previous_name={} new_serial={} zone_id={}",
            updated_zone.name,
            zone_name,
            new_serial,
            updated_zone.id
        );

        if let Err(e) =
            crate::notify::send_notify_after_update(Some(updated_zone.name.as_str())).await
        {
            log_warn!(
                "Failed to send NOTIFY for zone {}: {}",
                updated_zone.name,
                e
            );
        }

        // Re-send catalog NOTIFY when the zone was renamed
        if previous_name != updated_zone.name
            && let Err(e) = crate::notify::send_notify_after_update(Some(CATALOG_ZONE_NAME)).await
        {
            log_warn!("Failed to send NOTIFY for {}: {}", CATALOG_ZONE_NAME, e);
        }

        Ok(updated_zone)
    }
}

/// The serial is a system-managed version counter and cannot be set on update.
fn reject_serial(serial: Option<i32>) -> Result<(), ServiceError> {
    if serial.is_some() {
        return Err(ServiceError::invalid_input(
            "serial is managed automatically and cannot be set on update",
        ));
    }
    Ok(())
}
