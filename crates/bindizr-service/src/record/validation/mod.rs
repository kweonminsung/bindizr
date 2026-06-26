use bindizr_core::dns::name::{is_apex_name, is_same_or_subdomain_fqdn, to_fqdn};

use crate::{
    error::ServiceError,
    log_error,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
    validation::{MAX_DOMAIN_LEN, has_whitespace_or_control, validate_wire_labels},
};

mod record_value;

use record_value::{is_null_mx_record_value, record_values_equal, validate_record_value};

pub(super) struct NormalizedOwnerName {
    /// Name stored in the database according to the current relative-name policy.
    pub stored_name: String,
}

pub(super) fn normalize_record_owner_name(
    input_name: &str,
    zone_name: &str,
) -> Result<NormalizedOwnerName, ServiceError> {
    let input = input_name.trim();

    if input.is_empty() {
        return Err(ServiceError::BadRequest(
            "record name must not be empty".to_string(),
        ));
    }

    if has_whitespace_or_control(input) {
        return Err(ServiceError::BadRequest(
            "record name must not contain whitespace or control characters".to_string(),
        ));
    }

    let zone_fqdn = normalize_absolute_owner_fqdn(&to_fqdn(zone_name))?;
    let owner_fqdn = if input == "@" {
        zone_fqdn.clone()
    } else if input.ends_with('.') {
        normalize_absolute_owner_fqdn(input)?
    } else {
        let candidate = format!("{}.", input.to_ascii_lowercase());
        validate_wire_labels(&candidate, "record name")?;

        if is_same_or_subdomain_fqdn(&candidate, &zone_fqdn) {
            candidate
        } else {
            normalize_absolute_owner_fqdn(&format!("{}.{}", input, zone_fqdn))?
        }
    };

    if !is_same_or_subdomain_fqdn(&owner_fqdn, &zone_fqdn) {
        return Err(ServiceError::BadRequest(format!(
            "record name '{}' is outside zone '{}'",
            input_name, zone_name
        )));
    }

    Ok(NormalizedOwnerName {
        stored_name: owner_fqdn_to_stored_name(&owner_fqdn, &zone_fqdn),
    })
}

fn normalize_absolute_owner_fqdn(value: &str) -> Result<String, ServiceError> {
    let without_trailing_dot = value.trim().trim_end_matches('.');

    if without_trailing_dot.is_empty() {
        return Err(ServiceError::BadRequest(
            "record name must not be the root zone".to_string(),
        ));
    }

    if without_trailing_dot.len() > MAX_DOMAIN_LEN {
        return Err(ServiceError::BadRequest(
            "record name must be 253 bytes or fewer".to_string(),
        ));
    }

    let fqdn = format!("{}.", without_trailing_dot.to_ascii_lowercase());
    validate_wire_labels(&fqdn, "record name")?;
    Ok(fqdn)
}

fn owner_fqdn_to_stored_name(owner_fqdn: &str, zone_fqdn: &str) -> String {
    if owner_fqdn == zone_fqdn {
        return "@".to_string();
    }

    owner_fqdn
        .trim_end_matches(zone_fqdn)
        .trim_end_matches('.')
        .to_string()
}

pub(super) fn validate_record_add_constraints(
    zone: &Zone,
    zone_records: &[Record],
    owner_name: &str,
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
    except_record_id: Option<i32>,
) -> Result<NormalizedOwnerName, ServiceError> {
    let normalized_owner = normalize_record_owner_name(owner_name, &zone.name)?;

    if *record_type == RecordType::SOA {
        return Err(ServiceError::BadRequest(
            "Cannot create SOA record manually".to_string(),
        ));
    }

    validate_record_value(record_type, value, priority)?;

    if *record_type == RecordType::CNAME && normalized_owner.stored_name == "@" {
        return Err(ServiceError::BadRequest(
            "CNAME record cannot have '@' as name".to_string(),
        ));
    }

    let existing_records_with_name: Vec<_> = zone_records
        .iter()
        .filter(|r| {
            r.name.eq_ignore_ascii_case(&normalized_owner.stored_name)
                && except_record_id.map(|id| id != r.id).unwrap_or(true)
        })
        .collect();

    if existing_records_with_name.iter().any(|r| {
        r.record_type == *record_type
            && record_values_equal(&r.value, r.priority, value, priority, record_type)
    }) {
        return Err(ServiceError::BadRequest(format!(
            "Record '{}' {} '{}' already exists in this zone",
            owner_name, record_type, value
        )));
    }

    if *record_type == RecordType::MX {
        let adding_null_mx = is_null_mx_record_value(value, priority);
        let has_existing_null_mx = existing_records_with_name.iter().any(|r| {
            r.record_type == RecordType::MX && is_null_mx_record_value(&r.value, r.priority)
        });
        let has_existing_mx = existing_records_with_name
            .iter()
            .any(|r| r.record_type == RecordType::MX);

        if (adding_null_mx && has_existing_mx) || (!adding_null_mx && has_existing_null_mx) {
            return Err(ServiceError::BadRequest(format!(
                "Null MX record for '{}' cannot coexist with other MX records",
                owner_name
            )));
        }
    }

    if !existing_records_with_name.is_empty() {
        if *record_type == RecordType::CNAME {
            return Err(ServiceError::BadRequest(format!(
                "Another record with name '{}' already exists in this zone, so CNAME cannot be used",
                owner_name
            )));
        }
        if existing_records_with_name
            .iter()
            .any(|r| r.record_type == RecordType::CNAME)
        {
            return Err(ServiceError::BadRequest(format!(
                "A CNAME record with name '{}' already exists in this zone",
                owner_name
            )));
        }
    }

    if *record_type == RecordType::NS && normalized_owner.stored_name != "@" {
        return Err(ServiceError::BadRequest(
            "NS records must use apex owner name '@'".to_string(),
        ));
    }

    Ok(normalized_owner)
}

pub fn validate_delete_constraints(
    zone: &Zone,
    deleting_records: &[Record],
) -> Result<(), ServiceError> {
    if deleting_records
        .iter()
        .any(|r| r.record_type == RecordType::SOA)
    {
        return Err(ServiceError::BadRequest(
            "Cannot delete SOA record".to_string(),
        ));
    }

    for record in deleting_records {
        if record.record_type == RecordType::NS
            && is_apex_name(&record.name, &zone.name)
            && to_fqdn(&record.value).eq_ignore_ascii_case(&to_fqdn(&zone.primary_ns))
        {
            return Err(ServiceError::BadRequest(
                "Cannot delete NS record referenced by zone primary_ns".to_string(),
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_record_update_constraints(
    zone: &Zone,
    zone_records: &[Record],
    existing_record: &Record,
    updated_record: &Record,
) -> Result<NormalizedOwnerName, ServiceError> {
    // Preserve previous API semantics for SOA update attempts.
    if updated_record.record_type == RecordType::SOA {
        log_error!("Cannot update to SOA record type");
        return Err(ServiceError::BadRequest(
            "Cannot update to SOA record type".to_string(),
        ));
    }

    let normalized_owner = validate_record_add_constraints(
        zone,
        zone_records,
        &updated_record.name,
        &updated_record.record_type,
        &updated_record.value,
        updated_record.priority,
        Some(existing_record.id),
    )?;

    if existing_record.record_type == RecordType::NS
        && is_apex_name(&existing_record.name, &zone.name)
        && to_fqdn(&existing_record.value).eq_ignore_ascii_case(&to_fqdn(&zone.primary_ns))
    {
        let still_primary = updated_record.record_type == RecordType::NS
            && is_apex_name(&updated_record.name, &zone.name)
            && to_fqdn(&updated_record.value).eq_ignore_ascii_case(&to_fqdn(&zone.primary_ns));

        if !still_primary {
            return Err(ServiceError::BadRequest(
                "Cannot modify the NS record referenced by zone primary_ns".to_string(),
            ));
        }
    }

    Ok(normalized_owner)
}

pub async fn validate_add_constraints_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    owner_name: &str,
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
    except_record_id: Option<i32>,
) -> Result<(), ServiceError> {
    let zone_records = RepositoryService::get_records_by_zone_id_tx(tx, zone.id)
        .await
        .map_err(|e| {
            log_error!("Failed to load zone records: {}", e);
            ServiceError::Internal("Failed to load zone records".to_string())
        })?;

    validate_record_add_constraints(
        zone,
        &zone_records,
        owner_name,
        record_type,
        value,
        priority,
        except_record_id,
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests;
