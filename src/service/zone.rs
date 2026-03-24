use crate::{
    api::dto::CreateZoneRequest,
    database::model::{
        record::{Record, RecordType},
        zone::Zone,
        zone_change::ZoneChange,
        zone_snapshot::ZoneSnapshot,
    },
    dns, log_error, log_info, log_warn,
    service::{error::ServiceError, repository::RepositoryService},
};
use chrono::Utc;

/// Generate next serial number in YYYYMMDDNN format
fn generate_serial(current_serial: Option<i32>) -> i32 {
    let now = Utc::now();
    let date_prefix = now.format("%Y%m%d").to_string().parse::<i32>().unwrap();
    let base_serial = date_prefix * 100;

    match current_serial {
        Some(serial) => {
            // If same day, increment NN part
            if serial / 100 == date_prefix {
                serial + 1
            } else {
                // New day, reset to NN=00
                base_serial
            }
        }
        None => base_serial,
    }
}

fn to_fqdn(name: &str) -> String {
    name.trim_end_matches('.').to_string() + "."
}

fn to_relative_domain(fqdn: &str, zone_name: &str) -> String {
    let normalized_zone = to_fqdn(zone_name);

    if fqdn == normalized_zone {
        "@".to_string()
    } else if fqdn.ends_with(&normalized_zone) {
        let relative_part = &fqdn[..fqdn.len() - normalized_zone.len()];
        relative_part.trim_end_matches('.').to_string()
    } else {
        fqdn.trim_end_matches('.').to_string()
    }
}

fn is_in_bailiwick(name: &str, zone_name: &str) -> bool {
    to_fqdn(name)
        .to_ascii_lowercase()
        .ends_with(&to_fqdn(zone_name).to_ascii_lowercase())
}

fn has_glue(records: &[Record], host_name: &str) -> bool {
    records.iter().any(|r| {
        r.name.eq_ignore_ascii_case(host_name)
            && (r.record_type == RecordType::A || r.record_type == RecordType::AAAA)
    })
}

async fn save_zone_snapshot(zone: &Zone, serial: i32) -> Result<(), ServiceError> {
    RepositoryService::upsert_zone_snapshot(ZoneSnapshot {
        id: 0,
        zone_id: zone.id,
        serial,
        primary_ns: zone.primary_ns.clone(),
        admin_email: zone.admin_email.replace('@', "."),
        ttl: zone.ttl,
        refresh: zone.refresh,
        retry: zone.retry,
        expire: zone.expire,
        minimum_ttl: zone.minimum_ttl,
        created_at: Utc::now(),
    })
    .await
    .map_err(|e| {
        log_error!("Failed to save SOA snapshot: {}", e);
        ServiceError::Internal("Failed to save SOA snapshot".to_string())
    })?;

    Ok(())
}

#[derive(Clone)]
pub struct ZoneService;

impl ZoneService {
    pub async fn get_zones() -> Result<Vec<Zone>, ServiceError> {
        RepositoryService::get_all_zones().await.map_err(|e| {
            log_error!("Failed to fetch zones: {}", e);
            ServiceError::Internal("Failed to fetch zones".to_string())
        })
    }

    pub async fn get_zone(zone_name: &str) -> Result<Zone, ServiceError> {
        match RepositoryService::get_zone_by_name(zone_name).await {
            Ok(Some(zone)) => Ok(zone),
            Ok(None) => Err(ServiceError::NotFound(format!(
                "Zone with name '{}' not found",
                zone_name
            ))),
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                Err(ServiceError::Internal("Failed to fetch zone".to_string()))
            }
        }
    }

    pub async fn create_zone(
        create_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        // Check if zone already exists
        match RepositoryService::get_zone_by_name(&create_zone_request.name).await {
            Ok(Some(_)) => {
                log_error!("Zone with name {} already exists", create_zone_request.name);
                return Err(ServiceError::BadRequest(
                    "Zone with this name already exists".to_string(),
                ));
            }
            Ok(None) => (),
            Err(e) => {
                log_error!("Failed to check existing zone: {}", e);
                return Err(ServiceError::Internal("Failed to create zone".to_string()));
            }
        };

        // Generate serial if not provided
        let serial = match create_zone_request.serial {
            Some(s) => s,
            None => generate_serial(None),
        };

        // Create zone
        let created_zone = RepositoryService::create_zone(Zone {
            id: 0, // Will be set by the database
            name: create_zone_request.name.clone(),
            primary_ns: create_zone_request.primary_ns.clone(),
            admin_email: create_zone_request.admin_email.clone(),
            ttl: create_zone_request.ttl,
            serial,
            refresh: create_zone_request.refresh.unwrap_or(86400),
            retry: create_zone_request.retry.unwrap_or(7200),
            expire: create_zone_request.expire.unwrap_or(3_600_000),
            minimum_ttl: create_zone_request.minimum_ttl.unwrap_or(86400),
            created_at: Utc::now(), // Will be set by the database
        })
        .await
        .map_err(|e| {
            log_error!("Failed to create zone: {}", e);
            ServiceError::Internal("Failed to create zone".to_string())
        })?;

        // Log zone creation (structured logging)
        log_info!(
            "event=zone_create zone={} primary_ns={} admin_email={} serial={} zone_id={}",
            created_zone.name,
            created_zone.primary_ns,
            created_zone.admin_email,
            created_zone.serial,
            created_zone.id
        );

        // Keep zones.primary_ns aligned with at least one apex NS record in records table.
        let primary_ns_apex_record = Record {
            id: 0,
            name: "@".to_string(),
            record_type: RecordType::NS,
            value: create_zone_request.primary_ns.clone(),
            ttl: Some(create_zone_request.ttl),
            priority: None,
            zone_id: created_zone.id,
            created_at: Utc::now(),
        };

        RepositoryService::create_record(primary_ns_apex_record)
            .await
            .map_err(|e| {
                log_error!("Failed to create primary NS record: {}", e);
                ServiceError::Internal("Failed to create primary NS record".to_string())
            })?;

        save_zone_snapshot(&created_zone, created_zone.serial).await?;

        Ok(created_zone)
    }

    pub async fn update_zone(
        zone_name: &str,
        update_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        // Check if zone exists
        let existing_zone = match RepositoryService::get_zone_by_name(zone_name).await {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                log_error!("Zone with name '{}' not found", zone_name);
                return Err(ServiceError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ServiceError::Internal("Failed to update zone".to_string()));
            }
        };
        let zone_id = existing_zone.id;

        // Check if zone with the new name already exists (if name is being changed)
        if zone_name != update_zone_request.name {
            match RepositoryService::get_zone_by_name(&update_zone_request.name).await {
                Ok(Some(_)) => {
                    log_error!("Zone with name {} already exists", update_zone_request.name);
                    return Err(ServiceError::BadRequest(
                        "Zone with this name already exists".to_string(),
                    ));
                }
                Ok(None) => (),
                Err(e) => {
                    log_error!("Failed to check existing zone: {}", e);
                    return Err(ServiceError::Internal("Failed to update zone".to_string()));
                }
            };
        }

        // Auto-increment serial if not provided, or use existing if no change
        let new_serial = match update_zone_request.serial {
            Some(s) => s,
            None => generate_serial(Some(existing_zone.serial)),
        };

        let zone_records = RepositoryService::get_records_by_zone_id(zone_id)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch zone records: {}", e);
                ServiceError::Internal("Failed to update zone".to_string())
            })?;

        if is_in_bailiwick(&update_zone_request.primary_ns, &update_zone_request.name) {
            let relative = to_relative_domain(
                &to_fqdn(&update_zone_request.primary_ns),
                &update_zone_request.name,
            );
            if !has_glue(&zone_records, &relative) {
                return Err(ServiceError::BadRequest(format!(
                    "Primary NS '{}' is in-bailiwick and requires at least one A/AAAA glue record for '{}'",
                    update_zone_request.primary_ns, relative
                )));
            }
        }

        // Update zone
        let updated_zone = RepositoryService::update_zone(Zone {
            id: zone_id,
            name: update_zone_request.name.clone(),
            primary_ns: update_zone_request.primary_ns.clone(),
            admin_email: update_zone_request.admin_email.clone(),
            ttl: update_zone_request.ttl,
            serial: new_serial,
            refresh: update_zone_request.refresh.unwrap_or(86400),
            retry: update_zone_request.retry.unwrap_or(7200),
            expire: update_zone_request.expire.unwrap_or(3_600_000),
            minimum_ttl: update_zone_request.minimum_ttl.unwrap_or(86400),
            created_at: Utc::now(), // Will be set by the database
        })
        .await
        .map_err(|e| {
            log_error!("Failed to update zone: {}", e);
            ServiceError::Internal("Failed to update zone".to_string())
        })?;

        // Log zone update (structured logging)
        log_info!(
            "event=zone_update zone={} previous_name={} new_serial={} zone_id={}",
            update_zone_request.name,
            zone_name,
            new_serial,
            updated_zone.id
        );

        // Record zone changes for IXFR

        let has_primary_ns = zone_records.iter().any(|r| {
            r.record_type == RecordType::NS
                && r.name == "@"
                && to_fqdn(&r.value).eq_ignore_ascii_case(&to_fqdn(&updated_zone.primary_ns))
        });

        if !has_primary_ns {
            let primary_ns_record = Record {
                id: 0,
                name: "@".to_string(),
                record_type: RecordType::NS,
                value: updated_zone.primary_ns.clone(),
                ttl: Some(updated_zone.ttl),
                priority: None,
                zone_id,
                created_at: Utc::now(),
            };

            RepositoryService::create_record(primary_ns_record)
                .await
                .map_err(|e| {
                    log_error!("Failed to create primary NS record during update: {}", e);
                    ServiceError::Internal("Failed to keep primary NS consistency".to_string())
                })?;

            RepositoryService::create_zone_change(ZoneChange {
                id: 0,
                zone_id,
                serial: new_serial,
                operation: "ADD".to_string(),
                record_name: "@".to_string(),
                record_type: "NS".to_string(),
                record_value: updated_zone.primary_ns.clone(),
                record_ttl: Some(updated_zone.ttl),
                record_priority: None,
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change (ADD NS): {}", e);
                ServiceError::Internal("Failed to create zone change".to_string())
            })?;
        }

        let format_soa = |zone: &Zone| -> String {
            format!(
                "{} {} {} {} {} {} {}",
                zone.primary_ns,
                zone.admin_email.replace('@', "."),
                zone.serial,
                zone.refresh,
                zone.retry,
                zone.expire,
                zone.minimum_ttl
            )
        };

        // Delete old SOA record
        RepositoryService::create_zone_change(ZoneChange {
            id: 0,
            zone_id,
            serial: new_serial,
            operation: "DEL".to_string(),
            record_name: "@".to_string(),
            record_type: "SOA".to_string(),
            record_value: format_soa(&existing_zone),
            record_ttl: Some(existing_zone.ttl),
            record_priority: None,
        })
        .await
        .map_err(|e| {
            log_error!("Failed to create zone change (DEL SOA): {}", e);
            ServiceError::Internal("Failed to create zone change".to_string())
        })?;

        // Add new SOA record
        RepositoryService::create_zone_change(ZoneChange {
            id: 0,
            zone_id,
            serial: new_serial,
            operation: "ADD".to_string(),
            record_name: "@".to_string(),
            record_type: "SOA".to_string(),
            record_value: format_soa(&updated_zone),
            record_ttl: Some(updated_zone.ttl),
            record_priority: None,
        })
        .await
        .map_err(|e| {
            log_error!("Failed to create zone change (ADD SOA): {}", e);
            ServiceError::Internal("Failed to create zone change".to_string())
        })?;

        save_zone_snapshot(&updated_zone, new_serial).await?;

        // Send NOTIFY to secondary servers
        if let Err(e) = dns::xfr::notify::send_notify(Some(&updated_zone.name)).await {
            log_warn!(
                "Failed to send NOTIFY for zone {}: {}",
                updated_zone.name,
                e
            );
        }

        Ok(updated_zone)
    }

    pub async fn delete_zone(zone_name: &str) -> Result<(), ServiceError> {
        // Check if zone exists and get its ID
        let zone = match RepositoryService::get_zone_by_name(zone_name).await {
            Ok(Some(z)) => z,
            Ok(None) => {
                log_error!("Zone with name '{}' not found", zone_name);
                return Err(ServiceError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ServiceError::Internal("Failed to delete zone".to_string()));
            }
        };

        let zone_id = zone.id;
        let zone_name_clone = zone.name.clone();

        // Delete zone
        RepositoryService::delete_zone(zone_id).await.map_err(|e| {
            log_error!("Failed to delete zone: {}", e);
            ServiceError::Internal("Failed to delete zone".to_string())
        })?;

        // Log zone deletion (structured logging)
        log_info!(
            "event=zone_delete zone={} zone_id={}",
            zone_name_clone,
            zone_id
        );

        Ok(())
    }
}
