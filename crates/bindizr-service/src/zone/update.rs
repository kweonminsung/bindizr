use bindizr_core::dns::CATALOG_ZONE_NAME;

use super::{ZoneService, apex_ns_rrset_ttl};
use crate::{
    error::{ErrorCode, ServiceError},
    log_error, log_info, log_warn,
    model::{zone::Zone, zone_change::ZoneChange},
    record::RecordService,
    repository::RepositoryService,
    serial::generate_serial,
    types::{CreateZoneRequest, UpdateZonePatch},
    zone::validation::{ResolvedSoaTimers, resolve_soa_timers, validate_create_zone_request},
};

/// Outcome of the transactional part of a zone update.
struct AppliedZoneUpdate {
    zone: Zone,
    previous_name: String,
    new_serial: i32,
}

/// DEL(old)+ADD(new) apex SOA changes for an in-place zone row update, so IXFR
/// consumers replay the SOA transition.
pub(super) fn soa_replacement_changes(
    old_zone: &Zone,
    new_zone: &Zone,
    new_serial: i32,
) -> Result<Vec<ZoneChange>, ServiceError> {
    let change = |operation: &str, zone: &Zone| -> Result<ZoneChange, ServiceError> {
        Ok(ZoneChange {
            id: 0,
            zone_id: old_zone.id,
            serial: new_serial,
            operation: operation.to_string(),
            record_name: "@".to_string(),
            record_type: "SOA".to_string(),
            record_value: zone
                .soa_rdata()
                .map_err(|e| ServiceError::invalid_zone(e.to_string()))?,
            record_ttl: zone.ttl,
            record_priority: None,
        })
    };

    Ok(vec![
        change(ZoneChange::OP_DEL, old_zone)?,
        change(ZoneChange::OP_ADD, new_zone)?,
    ])
}

impl ZoneService {
    /// Full replacement (HTTP PUT): the request supplies every field.
    pub async fn update(
        zone_name: &str,
        request: &CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        reject_serial(request.serial)?;
        Self::update_locked(zone_name, |_existing| CreateZoneRequest {
            name: request.name.clone(),
            primary_ns: request.primary_ns.clone(),
            admin_email: request.admin_email.clone(),
            ttl: request.ttl,
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
    pub async fn patch(zone_name: &str, patch: &UpdateZonePatch) -> Result<Zone, ServiceError> {
        reject_serial(patch.serial)?;
        Self::update_locked(zone_name, |existing| CreateZoneRequest {
            name: patch
                .new_name
                .clone()
                .unwrap_or_else(|| existing.name.clone()),
            primary_ns: patch
                .primary_ns
                .clone()
                .unwrap_or_else(|| existing.primary_ns.clone()),
            admin_email: patch
                .admin_email
                .clone()
                .unwrap_or_else(|| existing.admin_email.clone()),
            ttl: patch.ttl.unwrap_or(existing.ttl),
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
            let existing_zone = ZoneService::get_by_name_tx(&mut tx, zone_name).await?;
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
                match RepositoryService::get_zone_by_name(&validated.name).await {
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
                        return Err(ServiceError::internal("Failed to update zone".to_string()));
                    }
                }
            }

            let new_serial = generate_serial(Some(existing_zone.serial))?;

            let updated_zone = RepositoryService::update_zone_tx(
                &mut tx,
                Zone {
                    id: zone_id,
                    name: validated.name.clone(),
                    primary_ns: validated.primary_ns.clone(),
                    admin_email: validated.admin_email.clone(),
                    ttl: validated.ttl,
                    serial: new_serial,
                    refresh: timers.refresh,
                    retry: timers.retry,
                    expire: timers.expire,
                    minimum_ttl: timers.minimum_ttl,
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
                    ServiceError::internal("Failed to update zone".to_string())
                }
            })?;

            // A rename / primary_ns change must keep an apex NS matching the new
            // primary_ns; only apex rows can satisfy that, so load just those.
            let apex_records =
                RepositoryService::get_records_by_zone_id_and_name_tx(&mut tx, zone_id, "@")
                    .await
                    .map_err(|e| {
                        log_error!("Failed to fetch apex records: {}", e);
                        ServiceError::internal("Failed to update zone".to_string())
                    })?;
            let has_primary_ns = apex_records
                .iter()
                .any(|r| updated_zone.is_primary_ns(&r.record_type, &r.name, &r.value));

            if !has_primary_ns {
                let primary_ns_record = updated_zone.primary_ns_record(apex_ns_rrset_ttl(
                    &updated_zone,
                    apex_records
                        .iter()
                        .map(|r| (&r.record_type, r.name.as_str(), r.ttl)),
                ));

                RecordService::insert_records_with_changes_tx(
                    &mut tx,
                    zone_id,
                    new_serial,
                    &[primary_ns_record],
                )
                .await
                .map_err(|e| {
                    log_error!("Failed to create primary NS record during update: {}", e);
                    ServiceError::internal("Failed to keep primary NS consistency".to_string())
                })?;
            }

            let changes = soa_replacement_changes(&existing_zone, &updated_zone, new_serial)?;

            RepositoryService::create_zone_changes_tx(&mut tx, &changes)
                .await
                .map_err(|e| {
                    log_error!("Failed to create zone changes: {}", e);
                    ServiceError::internal("Failed to create zone change".to_string())
                })?;

            ZoneService::save_snapshot_tx(&mut tx, &updated_zone, new_serial).await?;

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

        if let Err(e) = crate::notify::send_notify_after_update(Some(&updated_zone.name)).await {
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
