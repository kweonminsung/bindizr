use crate::{
    api::{dto::CreateRecordRequest, error::ApiError},
    database::{
        get_record_repository, get_zone_change_repository, get_zone_repository,
        get_zone_snapshot_repository,
        model::{
            record::{Record, RecordType},
            zone_change::ZoneChange,
            zone_snapshot::ZoneSnapshot,
        },
    },
    log_error, log_info, log_warn, xfr,
};
use chrono::Utc;

/// Generate next serial number in YYYYMMDDNN format
fn generate_serial(current_serial: i32) -> i32 {
    let now = Utc::now();
    let date_prefix = now.format("%Y%m%d").to_string().parse::<i32>().unwrap();
    let base_serial = date_prefix * 100;

    if base_serial > current_serial {
        // Today's base is ahead of current serial: reset to today's base
        base_serial
    } else {
        // Current serial is already at or past today's base: just increment
        current_serial + 1
    }
}

/// Convert name to FQDN by adding trailing dot
fn to_fqdn(name: &str) -> String {
    name.trim_end_matches('.').to_string() + "."
}

/// Convert FQDN to relative domain name within a zone
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

fn is_apex_name(name: &str, zone_name: &str) -> bool {
    name == "@" || to_fqdn(name).eq_ignore_ascii_case(&to_fqdn(zone_name))
}

fn is_in_bailiwick(name: &str, zone_name: &str) -> bool {
    to_fqdn(name)
        .to_ascii_lowercase()
        .ends_with(&to_fqdn(zone_name).to_ascii_lowercase())
}

fn has_glue_records_for(
    records: &[Record],
    host_relative_name: &str,
    except_id: Option<i32>,
) -> bool {
    records.iter().any(|r| {
        if except_id.is_some() && except_id == Some(r.id) {
            return false;
        }
        r.name.eq_ignore_ascii_case(host_relative_name)
            && (r.record_type == RecordType::A || r.record_type == RecordType::AAAA)
    })
}

async fn save_zone_snapshot(
    zone: &crate::database::model::zone::Zone,
    serial: i32,
) -> Result<(), ApiError> {
    let zone_snapshot_repository = get_zone_snapshot_repository();
    zone_snapshot_repository
        .upsert(ZoneSnapshot {
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
            ApiError::InternalServerError("Failed to save SOA snapshot".to_string())
        })?;

    Ok(())
}

#[derive(Clone)]
pub struct RecordService;

impl RecordService {
    pub async fn get_records(zone_name: Option<String>) -> Result<Vec<Record>, ApiError> {
        let zone_repository = get_zone_repository();
        let record_repository = get_record_repository();

        match zone_name {
            Some(name) => {
                // Check if zone exists and get zone_id
                let zone = match zone_repository.get_by_name(&name).await {
                    Ok(Some(z)) => z,
                    Ok(None) => {
                        return Err(ApiError::BadRequest(format!(
                            "Zone with name '{}' not found",
                            name
                        )));
                    }
                    Err(e) => {
                        log_error!("Failed to fetch zone: {}", e);
                        return Err(ApiError::InternalServerError(
                            "Failed to fetch zone".to_string(),
                        ));
                    }
                };

                // Fetch records by zone_id
                match record_repository.get_by_zone_id(zone.id).await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch records for zone {}: {}", name, e);
                        Err(ApiError::InternalServerError(format!(
                            "Failed to fetch records for zone {}",
                            name
                        )))
                    }
                }
            }
            None => {
                // Fetch all records
                match record_repository.get_all().await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch all records: {}", e);
                        Err(ApiError::InternalServerError(
                            "Failed to fetch all records".to_string(),
                        ))
                    }
                }
            }
        }
    }

    pub async fn get_record(name: &str, record_type: &str) -> Result<Record, ApiError> {
        let record_repository = get_record_repository();

        // Validate record type
        let record_type = RecordType::from_str(record_type)
            .map_err(|_| ApiError::BadRequest(format!("Invalid record type: {}", record_type)))?;

        match record_repository
            .get_by_name_and_type(name, &record_type)
            .await
        {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(ApiError::NotFound(format!(
                "Record with name '{}' and type '{}' not found",
                name, record_type
            ))),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch record".to_string(),
                ))
            }
        }
    }

    pub async fn create_record(
        create_record_request: &CreateRecordRequest,
    ) -> Result<Record, ApiError> {
        let zone_repository = get_zone_repository();
        let record_repository = get_record_repository();

        // Validate record type
        let record_type =
            RecordType::from_str(&create_record_request.record_type).map_err(|_| {
                ApiError::BadRequest(format!(
                    "Invalid record type: {}",
                    create_record_request.record_type
                ))
            })?;

        // CNAME validation for '@' name
        if record_type == RecordType::CNAME && create_record_request.name == "@" {
            return Err(ApiError::BadRequest(
                "CNAME record cannot have '@' as name".to_string(),
            ));
        }

        // SOA validation
        if record_type == RecordType::SOA {
            log_error!("Cannot create SOA record manually");
            return Err(ApiError::BadRequest(
                "Cannot create SOA record manually".to_string(),
            ));
        }

        // Check if zone exists
        let zone = match zone_repository
            .get_by_name(&create_record_request.zone_name)
            .await
        {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone with name '{}' not found",
                    create_record_request.zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to create record".to_string(),
                ));
            }
        };

        // CNAME validation
        let existing_records_in_zone = match record_repository.get_by_zone_id(zone.id).await {
            Ok(records) => records,
            Err(e) => {
                log_error!("Failed to check existing records: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to create record".to_string(),
                ));
            }
        };

        let existing_records_with_name: Vec<_> = existing_records_in_zone
            .iter()
            .filter(|r| r.name == create_record_request.name)
            .collect();

        if !existing_records_with_name.is_empty() {
            if record_type == RecordType::CNAME {
                return Err(ApiError::BadRequest(format!(
                    "A record with name '{}' already exists in this zone, so CNAME cannot be used",
                    create_record_request.name
                )));
            }
            if existing_records_with_name
                .iter()
                .any(|r| r.record_type == RecordType::CNAME)
            {
                return Err(ApiError::BadRequest(format!(
                    "A CNAME record with name '{}' already exists in this zone",
                    create_record_request.name
                )));
            }
        }

        if record_type == RecordType::NS {
            if !is_apex_name(&create_record_request.name, &zone.name) {
                return Err(ApiError::BadRequest(
                    "NS records must use apex owner name '@'".to_string(),
                ));
            }

            if is_in_bailiwick(&create_record_request.value, &zone.name) {
                let ns_host_relative =
                    to_relative_domain(&to_fqdn(&create_record_request.value), &zone.name);
                if !has_glue_records_for(&existing_records_in_zone, &ns_host_relative, None) {
                    return Err(ApiError::BadRequest(format!(
                        "In-bailiwick NS '{}' requires A/AAAA glue record '{}'",
                        create_record_request.value, ns_host_relative
                    )));
                }
            }
        }

        // Create record
        let created_record = record_repository
            .create(Record {
                id: 0, // Will be set by the database
                name: create_record_request.name.clone(),
                record_type,
                value: create_record_request.value.clone(),
                ttl: create_record_request.ttl,
                priority: create_record_request.priority,
                zone_id: zone.id,
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create record: {}", e);
                ApiError::InternalServerError("Failed to create record".to_string())
            })?;

        // Log record creation
        log_info!(
            "event=record_create zone={} name={} type={} value={} ttl={} priority={} record_id={}",
            zone.name,
            create_record_request.name,
            create_record_request.record_type,
            create_record_request.value,
            create_record_request
                .ttl
                .map_or("null".to_string(), |v| v.to_string()),
            create_record_request
                .priority
                .map_or("null".to_string(), |v| v.to_string()),
            created_record.id
        );

        // Increment zone serial so IXFR consumers can detect this change
        let new_serial = generate_serial(zone.serial);
        zone_repository
            .update(crate::database::model::zone::Zone {
                serial: new_serial,
                ..zone.clone()
            })
            .await
            .map_err(|e| {
                log_error!("Failed to update zone serial: {}", e);
                ApiError::InternalServerError("Failed to update zone serial".to_string())
            })?;

        // Record zone change for IXFR
        let zone_change_repository = get_zone_change_repository();
        zone_change_repository
            .create(ZoneChange {
                id: 0,
                zone_id: zone.id,
                serial: new_serial,
                operation: "ADD".to_string(),
                record_name: created_record.name.clone(),
                record_type: create_record_request.record_type.clone(),
                record_value: create_record_request.value.clone(),
                record_ttl: create_record_request.ttl,
                record_priority: create_record_request.priority,
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change: {}", e);
                ApiError::InternalServerError("Failed to create zone change".to_string())
            })?;

        save_zone_snapshot(&zone, new_serial).await?;

        // Send NOTIFY to secondary servers
        if let Err(e) = xfr::notify::send_notify(Some(&zone.name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
        }

        Ok(created_record)
    }

    pub async fn update_record(
        name: &str,
        record_type_str: &str,
        update_record_request: &CreateRecordRequest,
    ) -> Result<Record, ApiError> {
        let zone_repository = get_zone_repository();
        let record_repository = get_record_repository();

        // Validate old record type
        let old_record_type = RecordType::from_str(record_type_str).map_err(|_| {
            ApiError::BadRequest(format!("Invalid record type: {}", record_type_str))
        })?;

        // Check if record exists
        let existing_record = match record_repository
            .get_by_name_and_type(name, &old_record_type)
            .await
        {
            Ok(Some(record)) => record,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Record with name '{}' and type '{}' not found",
                    name, record_type_str
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch record".to_string(),
                ));
            }
        };

        let record_id = existing_record.id;

        // Load authoritative zone from the existing record to avoid cross-zone mismatches.
        let zone = match zone_repository.get_by_id(existing_record.zone_id).await {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        };

        if zone.name != update_record_request.zone_name {
            return Err(ApiError::BadRequest(format!(
                "Record belongs to zone '{}', but request zone is '{}'",
                zone.name, update_record_request.zone_name
            )));
        }

        // Validate record type
        let record_type =
            RecordType::from_str(&update_record_request.record_type).map_err(|_| {
                ApiError::BadRequest(format!(
                    "Invalid record type: {}",
                    update_record_request.record_type
                ))
            })?;

        // CNAME validation for '@' name
        if record_type == RecordType::CNAME && update_record_request.name == "@" {
            return Err(ApiError::BadRequest(
                "CNAME record cannot have '@' as name".to_string(),
            ));
        }

        // SOA validation
        if record_type == RecordType::SOA {
            log_error!("Cannot update to SOA record type");
            return Err(ApiError::BadRequest(
                "Cannot update to SOA record type".to_string(),
            ));
        }

        // CNAME validation
        let existing_records = match record_repository
            .get_by_name(&update_record_request.name)
            .await
        {
            Ok(records) => records,
            Err(e) => {
                log_error!("Failed to check existing record: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to update record".to_string(),
                ));
            }
        };

        let other_records_in_zone: Vec<_> = existing_records
            .into_iter()
            .filter(|r| r.id != record_id && r.zone_id == zone.id)
            .collect();

        if !other_records_in_zone.is_empty() {
            if record_type == RecordType::CNAME {
                return Err(ApiError::BadRequest(format!(
                    "A record with name '{}' already exists in this zone, so CNAME cannot be used",
                    update_record_request.name
                )));
            }
            if other_records_in_zone
                .iter()
                .any(|r| r.record_type == RecordType::CNAME)
            {
                return Err(ApiError::BadRequest(format!(
                    "A CNAME record with name '{}' already exists in this zone",
                    update_record_request.name
                )));
            }
        }

        let zone_records = match record_repository.get_by_zone_id(zone.id).await {
            Ok(records) => records,
            Err(e) => {
                log_error!("Failed to load zone records: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to update record".to_string(),
                ));
            }
        };

        if existing_record.record_type == RecordType::NS
            && is_apex_name(&existing_record.name, &zone.name)
            && to_fqdn(&existing_record.value).eq_ignore_ascii_case(&to_fqdn(&zone.primary_ns))
        {
            let still_primary = record_type == RecordType::NS
                && is_apex_name(&update_record_request.name, &zone.name)
                && to_fqdn(&update_record_request.value)
                    .eq_ignore_ascii_case(&to_fqdn(&zone.primary_ns));

            if !still_primary {
                return Err(ApiError::BadRequest(
                    "Cannot modify the NS record referenced by zone primary_ns".to_string(),
                ));
            }
        }

        if record_type == RecordType::NS {
            if !is_apex_name(&update_record_request.name, &zone.name) {
                return Err(ApiError::BadRequest(
                    "NS records must use apex owner name '@'".to_string(),
                ));
            }

            if is_in_bailiwick(&update_record_request.value, &zone.name) {
                let ns_host_relative =
                    to_relative_domain(&to_fqdn(&update_record_request.value), &zone.name);
                if !has_glue_records_for(&zone_records, &ns_host_relative, Some(record_id)) {
                    return Err(ApiError::BadRequest(format!(
                        "In-bailiwick NS '{}' requires A/AAAA glue record '{}'",
                        update_record_request.value, ns_host_relative
                    )));
                }
            }
        }

        // Update record
        let updated_record = record_repository
            .update(Record {
                id: record_id,
                name: update_record_request.name.clone(),
                record_type,
                value: update_record_request.value.clone(),
                ttl: update_record_request.ttl,
                priority: update_record_request.priority,
                zone_id: zone.id,
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to update record: {}", e);
                ApiError::InternalServerError("Failed to update record".to_string())
            })?;

        // Log record update
        log_info!(
            "event=record_update zone={} name={} type={} old_value={} new_value={} ttl={} priority={} record_id={}",
            zone.name,
            update_record_request.name,
            update_record_request.record_type,
            existing_record.value,
            update_record_request.value,
            update_record_request
                .ttl
                .map_or("null".to_string(), |v| v.to_string()),
            update_record_request
                .priority
                .map_or("null".to_string(), |v| v.to_string()),
            updated_record.id
        );

        // Increment zone serial so IXFR consumers can detect this change
        let new_serial = generate_serial(zone.serial);
        zone_repository
            .update(crate::database::model::zone::Zone {
                serial: new_serial,
                ..zone.clone()
            })
            .await
            .map_err(|e| {
                log_error!("Failed to update zone serial: {}", e);
                ApiError::InternalServerError("Failed to update zone serial".to_string())
            })?;

        // Record zone changes for IXFR
        let zone_change_repository = get_zone_change_repository();

        // Delete old record
        zone_change_repository
            .create(ZoneChange {
                id: 0,
                zone_id: zone.id,
                serial: new_serial,
                operation: "DEL".to_string(),
                record_name: existing_record.name.clone(),
                record_type: existing_record.record_type.to_string(),
                record_value: existing_record.value.clone(),
                record_ttl: existing_record.ttl,
                record_priority: existing_record.priority,
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change (DEL): {}", e);
                ApiError::InternalServerError("Failed to create zone change".to_string())
            })?;

        // Add new record
        zone_change_repository
            .create(ZoneChange {
                id: 0,
                zone_id: zone.id,
                serial: new_serial,
                operation: "ADD".to_string(),
                record_name: updated_record.name.clone(),
                record_type: update_record_request.record_type.clone(),
                record_value: update_record_request.value.clone(),
                record_ttl: update_record_request.ttl,
                record_priority: update_record_request.priority,
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change (ADD): {}", e);
                ApiError::InternalServerError("Failed to create zone change".to_string())
            })?;

        save_zone_snapshot(&zone, new_serial).await?;

        // Send NOTIFY to secondary servers
        if let Err(e) = xfr::notify::send_notify(Some(&zone.name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
        }

        Ok(updated_record)
    }

    pub async fn delete_record(name: &str, record_type_str: &str) -> Result<(), ApiError> {
        let zone_repository = get_zone_repository();
        let record_repository = get_record_repository();

        // Valid record type
        let record_type = RecordType::from_str(record_type_str).map_err(|_| {
            ApiError::BadRequest(format!("Invalid record type: {}", record_type_str))
        })?;

        // Check if record exists
        let existing_record = match record_repository
            .get_by_name_and_type(name, &record_type)
            .await
        {
            Ok(Some(record)) => record,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Record with name '{}' and type '{}' not found",
                    name, record_type_str
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch record".to_string(),
                ));
            }
        };

        // Get zone name for history
        let zone = match zone_repository.get_by_id(existing_record.zone_id).await {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                log_error!(
                    "Zone with id '{}' not found for record '{}'",
                    existing_record.zone_id,
                    name
                );
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone for record".to_string(),
                ));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        };

        let record_id = existing_record.id;
        let record_name = existing_record.name.clone();
        let record_type_str_clone = record_type_str.to_string();

        // Prevent deletion of SOA records
        if existing_record.record_type == RecordType::SOA {
            log_error!("Cannot delete SOA record");
            return Err(ApiError::BadRequest("Cannot delete SOA record".to_string()));
        }

        if existing_record.record_type == RecordType::NS
            && is_apex_name(&existing_record.name, &zone.name)
            && to_fqdn(&existing_record.value).eq_ignore_ascii_case(&to_fqdn(&zone.primary_ns))
        {
            return Err(ApiError::BadRequest(
                "Cannot delete NS record referenced by zone primary_ns".to_string(),
            ));
        }

        if existing_record.record_type == RecordType::A
            || existing_record.record_type == RecordType::AAAA
        {
            let zone_records = match record_repository.get_by_zone_id(zone.id).await {
                Ok(records) => records,
                Err(e) => {
                    log_error!("Failed to load zone records: {}", e);
                    return Err(ApiError::InternalServerError(
                        "Failed to delete record".to_string(),
                    ));
                }
            };

            let impacted_ns = zone_records.iter().filter(|r| {
                r.record_type == RecordType::NS
                    && is_apex_name(&r.name, &zone.name)
                    && is_in_bailiwick(&r.value, &zone.name)
            });

            for ns in impacted_ns {
                let required_host = to_relative_domain(&to_fqdn(&ns.value), &zone.name);
                if required_host.eq_ignore_ascii_case(&existing_record.name)
                    && !has_glue_records_for(
                        &zone_records,
                        &required_host,
                        Some(existing_record.id),
                    )
                {
                    return Err(ApiError::BadRequest(format!(
                        "Cannot remove last glue record '{}' required by NS '{}'",
                        required_host, ns.value
                    )));
                }
            }
        }

        // Delete record
        record_repository.delete(record_id).await.map_err(|e| {
            log_error!("Failed to delete record: {}", e);
            ApiError::InternalServerError("Failed to delete record".to_string())
        })?;

        // Log record deletion
        log_info!(
            "event=record_delete zone={} name={} type={} value={} record_id={}",
            zone.name,
            record_name,
            record_type_str_clone,
            existing_record.value,
            existing_record.id
        );

        // Increment zone serial so IXFR consumers can detect this change
        let new_serial = generate_serial(zone.serial);
        zone_repository
            .update(crate::database::model::zone::Zone {
                serial: new_serial,
                ..zone.clone()
            })
            .await
            .map_err(|e| {
                log_error!("Failed to update zone serial: {}", e);
                ApiError::InternalServerError("Failed to update zone serial".to_string())
            })?;

        // Record zone change for IXFR
        let zone_change_repository = get_zone_change_repository();
        zone_change_repository
            .create(ZoneChange {
                id: 0,
                zone_id: zone.id,
                serial: new_serial,
                operation: "DEL".to_string(),
                record_name: existing_record.name.clone(),
                record_type: existing_record.record_type.to_string(),
                record_value: existing_record.value.clone(),
                record_ttl: existing_record.ttl,
                record_priority: existing_record.priority,
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change: {}", e);
                ApiError::InternalServerError("Failed to create zone change".to_string())
            })?;

        save_zone_snapshot(&zone, new_serial).await?;

        // Send NOTIFY to secondary servers
        if let Err(e) = xfr::notify::send_notify(Some(&zone.name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
        }

        Ok(())
    }
}
