use std::net::{Ipv4Addr, Ipv6Addr};

use bindizr_core::dns::name::{
    is_apex_name, is_same_or_subdomain_fqdn, split_presentation_labels, to_fqdn,
};

use crate::{
    error::ServiceError,
    log_error,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
};

const MAX_DNS_LABEL_LEN: usize = 63;
const MAX_DOMAIN_LEN: usize = 253;

pub(super) struct NormalizedOwnerName {
    /// Fully-qualified, lowercase name used for comparison and validation.
    pub fqdn: String,
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
        validate_owner_fqdn(&candidate)?;

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
        fqdn: owner_fqdn,
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
    validate_owner_fqdn(&fqdn)?;
    Ok(fqdn)
}

fn validate_owner_fqdn(fqdn: &str) -> Result<(), ServiceError> {
    for label in split_presentation_labels(fqdn.trim_end_matches('.'))
        .map_err(|e| ServiceError::BadRequest(e.to_string()))?
    {
        if label.is_empty() {
            return Err(ServiceError::BadRequest(
                "record name must not contain empty labels".to_string(),
            ));
        }

        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(ServiceError::BadRequest(
                "record name labels must be 63 bytes or fewer".to_string(),
            ));
        }
    }

    Ok(())
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

fn has_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
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

    validate_record_value(record_type, value)?;

    if *record_type == RecordType::CNAME && normalized_owner.stored_name == "@" {
        return Err(ServiceError::BadRequest(
            "CNAME record cannot have '@' as name".to_string(),
        ));
    }

    let existing_records_with_name: Vec<_> = zone_records
        .iter()
        .filter(|r| {
            normalize_record_owner_name(&r.name, &zone.name)
                .ok()
                .is_some_and(|owner| owner.fqdn == normalized_owner.fqdn)
                && except_record_id.map(|id| id != r.id).unwrap_or(true)
        })
        .collect();

    if existing_records_with_name.iter().any(|r| {
        r.record_type == *record_type
            && record_values_equal(&r.value, value, record_type)
            && r.priority == priority
    }) {
        return Err(ServiceError::BadRequest(format!(
            "Record '{}' {} '{}' already exists in this zone",
            owner_name, record_type, value
        )));
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

fn validate_record_value(record_type: &RecordType, value: &str) -> Result<(), ServiceError> {
    match record_type {
        RecordType::A => value.parse::<Ipv4Addr>().map(|_| ()).map_err(|_| {
            ServiceError::BadRequest(format!(
                "A record value must be a valid IPv4 address: {}",
                value
            ))
        }),
        RecordType::AAAA => value.parse::<Ipv6Addr>().map(|_| ()).map_err(|_| {
            ServiceError::BadRequest(format!(
                "AAAA record value must be a valid IPv6 address: {}",
                value
            ))
        }),
        RecordType::CNAME => validate_domain_record_value("CNAME record value", value),
        _ => Ok(()),
    }
}

fn validate_domain_record_value(field: &str, value: &str) -> Result<(), ServiceError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must not be empty",
            field
        )));
    }

    if has_whitespace_or_control(trimmed) {
        return Err(ServiceError::BadRequest(format!(
            "{} must not contain whitespace or control characters",
            field
        )));
    }

    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing_dot.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must not be the root zone",
            field
        )));
    }

    if without_trailing_dot.len() > MAX_DOMAIN_LEN {
        return Err(ServiceError::BadRequest(format!(
            "{} must be 253 bytes or fewer",
            field
        )));
    }

    for label in split_presentation_labels(without_trailing_dot)
        .map_err(|e| ServiceError::BadRequest(e.to_string()))?
    {
        validate_domain_record_label(field, &label)?;
    }

    Ok(())
}

fn validate_domain_record_label(field: &str, label: &str) -> Result<(), ServiceError> {
    if label.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must not contain empty labels",
            field
        )));
    }

    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must be 63 bytes or fewer",
            field
        )));
    }

    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must contain only ASCII letters, digits, or hyphens",
            field
        )));
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must not start or end with hyphens",
            field
        )));
    }

    Ok(())
}

pub fn validate_record_delete_constraints(
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

pub async fn validate_record_add_constraints_tx(
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

fn record_values_equal(left: &str, right: &str, record_type: &RecordType) -> bool {
    canonical_record_value(left, record_type) == canonical_record_value(right, record_type)
}

fn canonical_record_value(value: &str, record_type: &RecordType) -> String {
    match record_type {
        RecordType::CNAME | RecordType::NS | RecordType::PTR => to_fqdn(value).to_ascii_lowercase(),
        RecordType::MX | RecordType::SRV => canonical_last_name_field(value),
        _ => value.to_string(),
    }
}

fn canonical_last_name_field(value: &str) -> String {
    let mut fields = value
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let Some(last) = fields.pop() else {
        return value.to_string();
    };

    fields.push(to_fqdn(&last).to_ascii_lowercase());
    fields.join(" ")
}

#[cfg(test)]
mod tests {
    use super::{normalize_record_owner_name, record_values_equal};
    use crate::model::record::RecordType;

    #[test]
    fn normalize_record_owner_name_accepts_relative_and_in_bailiwick_absolute_names() {
        let zone = "test.example.com";

        let apex = normalize_record_owner_name("@", zone).unwrap();
        assert_eq!(apex.fqdn, "test.example.com.");
        assert_eq!(apex.stored_name, "@");

        let relative = normalize_record_owner_name("a1", zone).unwrap();
        assert_eq!(relative.fqdn, "a1.test.example.com.");
        assert_eq!(relative.stored_name, "a1");

        let relative_with_zone_suffix =
            normalize_record_owner_name("A1.Test.Example.Com", zone).unwrap();
        assert_eq!(relative_with_zone_suffix.fqdn, "a1.test.example.com.");
        assert_eq!(relative_with_zone_suffix.stored_name, "a1");

        let absolute = normalize_record_owner_name("A1.Test.Example.Com.", zone).unwrap();
        assert_eq!(absolute.fqdn, "a1.test.example.com.");
        assert_eq!(absolute.stored_name, "a1");
    }

    #[test]
    fn normalize_record_owner_name_rejects_out_of_bailiwick_absolute_names() {
        let zone = "test.example.com";

        for name in [
            "a1.",
            "example.com.",
            "a1.example.com.",
            "other.com.",
            "a1.other.com.",
            "badtest.example.com.",
        ] {
            assert!(
                normalize_record_owner_name(name, zone).is_err(),
                "{name} should be rejected"
            );
        }
    }

    #[test]
    fn record_values_equal_normalizes_name_like_values() {
        assert!(record_values_equal(
            "Target.Example.Net",
            "target.example.net.",
            &RecordType::CNAME
        ));
        assert!(record_values_equal(
            "10 mail.example.com",
            "10 mail.example.com.",
            &RecordType::MX
        ));
        assert!(record_values_equal(
            "10 5 5060 sip.example.com",
            "10 5 5060 sip.example.com.",
            &RecordType::SRV
        ));
        assert!(!record_values_equal(
            "Token=ABC",
            "token=abc",
            &RecordType::TXT
        ));
    }
}
