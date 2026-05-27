use crate::{
    error::ServiceError,
    log_error,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
    utils::{has_glue_records_for, is_apex_name, is_in_bailiwick, to_fqdn, to_relative_domain},
};
use std::collections::HashSet;

pub(super) fn validate_glue_invariants(
    zone: &Zone,
    records: &[Record],
) -> Result<(), ServiceError> {
    let remaining_in_bailiwick_apex_ns = records.iter().filter(|r| {
        r.record_type == RecordType::NS
            && is_apex_name(&r.name, &zone.name)
            && is_in_bailiwick(&r.value, &zone.name)
    });

    for ns in remaining_in_bailiwick_apex_ns {
        let required_host = to_relative_domain(&to_fqdn(&ns.value), &zone.name);
        if !has_glue_records_for(records, &required_host, None) {
            return Err(ServiceError::BadRequest(format!(
                "Cannot remove last glue record '{}' required by NS '{}'",
                required_host, ns.value
            )));
        }
    }

    Ok(())
}

pub(super) fn validate_record_add_constraints(
    zone: &Zone,
    zone_records: &[Record],
    owner_name: &str,
    record_type: &RecordType,
    value: &str,
    except_record_id: Option<i32>,
) -> Result<(), ServiceError> {
    if *record_type == RecordType::SOA {
        return Err(ServiceError::BadRequest(
            "Cannot create SOA record manually".to_string(),
        ));
    }

    if *record_type == RecordType::CNAME && owner_name == "@" {
        return Err(ServiceError::BadRequest(
            "CNAME record cannot have '@' as name".to_string(),
        ));
    }

    let existing_records_with_name: Vec<_> = zone_records
        .iter()
        .filter(|r| {
            r.name.eq_ignore_ascii_case(owner_name)
                && except_record_id.map(|id| id != r.id).unwrap_or(true)
        })
        .collect();

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

    if *record_type == RecordType::NS {
        if !is_apex_name(owner_name, &zone.name) {
            return Err(ServiceError::BadRequest(
                "NS records must use apex owner name '@'".to_string(),
            ));
        }

        if is_in_bailiwick(value, &zone.name) {
            let ns_host_relative = to_relative_domain(&to_fqdn(value), &zone.name);
            if !has_glue_records_for(zone_records, &ns_host_relative, None) {
                return Err(ServiceError::BadRequest(format!(
                    "In-bailiwick NS '{}' requires A/AAAA glue record '{}'",
                    value, ns_host_relative
                )));
            }
        }
    }

    Ok(())
}

pub fn validate_record_delete_constraints(
    zone: &Zone,
    zone_records: &[Record],
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

    let deleting_ids: HashSet<i32> = deleting_records.iter().map(|r| r.id).collect();
    let remaining_records: Vec<Record> = zone_records
        .iter()
        .filter(|r| !deleting_ids.contains(&r.id))
        .cloned()
        .collect();

    validate_glue_invariants(zone, &remaining_records)
}

pub(super) fn validate_record_update_constraints(
    zone: &Zone,
    zone_records: &[Record],
    existing_record: &Record,
    updated_record: &Record,
) -> Result<(), ServiceError> {
    // Preserve previous API semantics for SOA update attempts.
    if updated_record.record_type == RecordType::SOA {
        log_error!("Cannot update to SOA record type");
        return Err(ServiceError::BadRequest(
            "Cannot update to SOA record type".to_string(),
        ));
    }

    validate_record_add_constraints(
        zone,
        zone_records,
        &updated_record.name,
        &updated_record.record_type,
        &updated_record.value,
        Some(existing_record.id),
    )?;

    let records_after_update: Vec<Record> = zone_records
        .iter()
        .map(|record| {
            if record.id == existing_record.id {
                updated_record.clone()
            } else {
                record.clone()
            }
        })
        .collect();

    validate_glue_invariants(zone, &records_after_update)?;

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

    Ok(())
}

pub async fn validate_record_add_constraints_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    owner_name: &str,
    record_type: &RecordType,
    value: &str,
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
        except_record_id,
    )
}
