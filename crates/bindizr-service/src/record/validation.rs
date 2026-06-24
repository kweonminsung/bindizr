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

fn validate_record_value(
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
) -> Result<(), ServiceError> {
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
        RecordType::NS => validate_domain_record_value("NS record value", value),
        RecordType::PTR => validate_domain_record_value("PTR record value", value),
        RecordType::MX => validate_mx_record_value(value, priority),
        RecordType::SRV => validate_srv_record_value(value, priority),
        _ => Ok(()),
    }
}

fn validate_mx_record_value(
    value: &str,
    fallback_priority: Option<i32>,
) -> Result<(), ServiceError> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    match fields.as_slice() {
        [priority, target] => {
            if fallback_priority.is_some() {
                return Err(ServiceError::BadRequest(
                    "MX priority must be provided either inline or in the priority field, not both"
                        .to_string(),
                ));
            }
            validate_u16_record_field("MX priority", priority)?;
            validate_domain_record_value("MX record target", target)
        }
        [target] => {
            validate_optional_u16_record_field("MX priority", fallback_priority)?;
            validate_domain_record_value("MX record target", target)
        }
        _ => Err(ServiceError::BadRequest(format!(
            "MX record value must be '<priority> <target>' or '<target>': {value}"
        ))),
    }
}

fn validate_srv_record_value(
    value: &str,
    fallback_priority: Option<i32>,
) -> Result<(), ServiceError> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    let (weight, port, target) = match fields.as_slice() {
        [priority, weight, port, target] => {
            if fallback_priority.is_some() {
                return Err(ServiceError::BadRequest(
                    "SRV priority must be provided either inline or in the priority field, not both"
                        .to_string(),
                ));
            }
            validate_u16_record_field("SRV priority", priority)?;
            (*weight, *port, *target)
        }
        [weight, port, target] => {
            validate_optional_u16_record_field("SRV priority", fallback_priority)?;
            (*weight, *port, *target)
        }
        _ => {
            return Err(ServiceError::BadRequest(format!(
                "SRV record value must be '<priority> <weight> <port> <target>' or '<weight> <port> <target>': {value}"
            )));
        }
    };

    validate_u16_record_field("SRV weight", weight)?;
    validate_u16_record_field("SRV port", port)?;
    validate_domain_record_value("SRV record target", target)
}

fn validate_optional_u16_record_field(field: &str, value: Option<i32>) -> Result<(), ServiceError> {
    u16::try_from(value.unwrap_or(10))
        .map(|_| ())
        .map_err(|_| ServiceError::BadRequest(format!("{field} must be between 0 and 65535")))
}

fn validate_u16_record_field(field: &str, value: &str) -> Result<(), ServiceError> {
    value.parse::<u16>().map(|_| ()).map_err(|_| {
        ServiceError::BadRequest(format!(
            "{field} must be an unsigned 16-bit integer: {value}"
        ))
    })
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

    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must contain only ASCII letters, digits, hyphens, or underscores",
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

fn record_values_equal(
    left: &str,
    left_priority: Option<i32>,
    right: &str,
    right_priority: Option<i32>,
    record_type: &RecordType,
) -> bool {
    canonical_record_value(left, left_priority, record_type)
        == canonical_record_value(right, right_priority, record_type)
}

fn canonical_record_value(
    value: &str,
    fallback_priority: Option<i32>,
    record_type: &RecordType,
) -> String {
    match record_type {
        RecordType::CNAME | RecordType::NS | RecordType::PTR => to_fqdn(value).to_ascii_lowercase(),
        RecordType::MX => canonical_mx_record_value(value, fallback_priority),
        RecordType::SRV => canonical_srv_record_value(value, fallback_priority),
        _ => value.to_string(),
    }
}

fn canonical_mx_record_value(value: &str, fallback_priority: Option<i32>) -> String {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    match fields.as_slice() {
        [priority, target] => format!(
            "{} {}",
            canonical_u16_field(priority),
            to_fqdn(target).to_ascii_lowercase()
        ),
        [target] => format!(
            "{} {}",
            canonical_optional_u16_field(fallback_priority),
            to_fqdn(target).to_ascii_lowercase()
        ),
        _ => canonical_last_name_field(value),
    }
}

fn canonical_srv_record_value(value: &str, fallback_priority: Option<i32>) -> String {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    match fields.as_slice() {
        [priority, weight, port, target] => format!(
            "{} {} {} {}",
            canonical_u16_field(priority),
            canonical_u16_field(weight),
            canonical_u16_field(port),
            to_fqdn(target).to_ascii_lowercase()
        ),
        [weight, port, target] => format!(
            "{} {} {} {}",
            canonical_optional_u16_field(fallback_priority),
            canonical_u16_field(weight),
            canonical_u16_field(port),
            to_fqdn(target).to_ascii_lowercase()
        ),
        _ => canonical_last_name_field(value),
    }
}

fn canonical_optional_u16_field(value: Option<i32>) -> String {
    u16::try_from(value.unwrap_or(10))
        .map(|value| value.to_string())
        .unwrap_or_else(|_| value.unwrap_or(10).to_string())
}

fn canonical_u16_field(value: &str) -> String {
    value
        .parse::<u16>()
        .map(|value| value.to_string())
        .unwrap_or_else(|_| value.to_string())
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
    use chrono::Utc;

    use super::{
        normalize_record_owner_name, record_values_equal, validate_delete_constraints,
        validate_record_add_constraints, validate_record_value,
    };
    use crate::model::{
        record::{Record, RecordType},
        zone::Zone,
    };

    #[test]
    fn normalize_record_owner_name_accepts_relative_and_in_bailiwick_absolute_names() {
        let zone = "test.example.com";

        let apex = normalize_record_owner_name("@", zone).unwrap();
        assert_eq!(apex.stored_name, "@");

        let relative = normalize_record_owner_name("a1", zone).unwrap();
        assert_eq!(relative.stored_name, "a1");

        let relative_with_zone_suffix =
            normalize_record_owner_name("A1.Test.Example.Com", zone).unwrap();
        assert_eq!(relative_with_zone_suffix.stored_name, "a1");

        let absolute = normalize_record_owner_name("A1.Test.Example.Com.", zone).unwrap();
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
            None,
            "target.example.net.",
            None,
            &RecordType::CNAME
        ));
        assert!(record_values_equal(
            "10 mail.example.com",
            None,
            "10 mail.example.com.",
            None,
            &RecordType::MX
        ));
        assert!(record_values_equal(
            "mail.example.com",
            Some(10),
            "010 mail.example.com.",
            None,
            &RecordType::MX
        ));
        assert!(record_values_equal(
            "10 5 5060 sip.example.com",
            None,
            "10 5 5060 sip.example.com.",
            None,
            &RecordType::SRV
        ));
        assert!(record_values_equal(
            "5 5060 sip.example.com",
            Some(10),
            "010 005 5060 sip.example.com.",
            None,
            &RecordType::SRV
        ));
        assert!(!record_values_equal(
            "Token=ABC",
            None,
            "token=abc",
            None,
            &RecordType::TXT
        ));
    }

    #[test]
    fn validate_cname_value_accepts_underscore_labels() {
        assert!(
            validate_record_value(
                &RecordType::CNAME,
                "_acme-challenge.validation.example.",
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_cname_value_rejects_invalid_domain_forms() {
        for value in [
            "",
            ".",
            "bad target.example.com",
            "bad..example.com",
            "-bad.example.com",
            "bad-.example.com",
        ] {
            assert!(
                validate_record_value(&RecordType::CNAME, value, None).is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn validate_ns_and_ptr_values_reject_invalid_domain_forms() {
        for record_type in [RecordType::NS, RecordType::PTR] {
            for value in [
                "",
                ".",
                "bad target.example.com",
                "bad..example.com",
                "-bad.example.com",
                "bad-.example.com",
            ] {
                assert!(
                    validate_record_value(&record_type, value, None).is_err(),
                    "{record_type} value {value:?} should be rejected"
                );
            }
        }
    }

    #[test]
    fn validate_mx_value_accepts_full_and_split_priority_forms() {
        assert!(validate_record_value(&RecordType::MX, "10 mail.example.com", None).is_ok());
        assert!(validate_record_value(&RecordType::MX, "mail.example.com", Some(10)).is_ok());
        assert!(validate_record_value(&RecordType::MX, "mail.example.com", None).is_ok());
    }

    #[test]
    fn validate_mx_value_rejects_invalid_forms() {
        for (value, priority) in [
            ("", None),
            ("10 mail.example.com extra", None),
            ("not-a-priority mail.example.com", None),
            ("65536 mail.example.com", None),
            ("10 bad target.example.com", None),
            ("10 bad..example.com", None),
            ("10 mail.example.com", Some(10)),
            ("mail.example.com", Some(-1)),
            ("mail.example.com", Some(65_536)),
        ] {
            assert!(
                validate_record_value(&RecordType::MX, value, priority).is_err(),
                "MX value {value:?} with priority {priority:?} should be rejected"
            );
        }
    }

    #[test]
    fn validate_srv_value_accepts_full_and_split_priority_forms() {
        assert!(validate_record_value(&RecordType::SRV, "10 5 5060 sip.example.com", None).is_ok());
        assert!(
            validate_record_value(&RecordType::SRV, "5 5060 sip.example.com", Some(10)).is_ok()
        );
        assert!(validate_record_value(&RecordType::SRV, "5 5060 sip.example.com", None).is_ok());
    }

    #[test]
    fn validate_srv_value_rejects_invalid_forms() {
        for (value, priority) in [
            ("", None),
            ("10 5", None),
            ("10 5 5060 sip.example.com extra", None),
            ("not-a-priority 5 5060 sip.example.com", None),
            ("10 not-a-weight 5060 sip.example.com", None),
            ("10 5 not-a-port sip.example.com", None),
            ("65536 5 5060 sip.example.com", None),
            ("10 65536 5060 sip.example.com", None),
            ("10 5 65536 sip.example.com", None),
            ("10 5 5060 bad target.example.com", None),
            ("10 5 5060 bad..example.com", None),
            ("10 5 5060 sip.example.com", Some(10)),
            ("5 5060 sip.example.com", Some(-1)),
            ("5 5060 sip.example.com", Some(65_536)),
        ] {
            assert!(
                validate_record_value(&RecordType::SRV, value, priority).is_err(),
                "SRV value {value:?} with priority {priority:?} should be rejected"
            );
        }
    }

    #[test]
    fn validate_record_add_constraints_enforces_cname_and_ns_owner_rules() {
        let zone = test_zone();

        let cname_at_apex = validate_record_add_constraints(
            &zone,
            &[],
            "@",
            &RecordType::CNAME,
            "target.example.com",
            None,
            None,
        );
        assert!(cname_at_apex.is_err());

        let ns_below_apex = validate_record_add_constraints(
            &zone,
            &[],
            "child",
            &RecordType::NS,
            "ns.example.com",
            None,
            None,
        );
        assert!(ns_below_apex.is_err());

        let existing_a = test_record(1, "www", RecordType::A, "192.0.2.10", None);
        let cname_conflict = validate_record_add_constraints(
            &zone,
            &[existing_a],
            "www",
            &RecordType::CNAME,
            "target.example.com",
            None,
            None,
        );
        assert!(cname_conflict.is_err());
    }

    #[test]
    fn validate_record_add_constraints_rejects_wire_equivalent_mx_and_srv_duplicates() {
        let zone = test_zone();

        let existing_mx = test_record(1, "@", RecordType::MX, "mail.example.com", Some(10));
        let duplicate_mx = validate_record_add_constraints(
            &zone,
            &[existing_mx],
            "@",
            &RecordType::MX,
            "10 mail.example.com",
            Some(10),
            None,
        );
        assert!(duplicate_mx.is_err());

        let existing_srv = test_record(
            2,
            "_sip._tcp",
            RecordType::SRV,
            "5 5060 sip.example.com",
            Some(10),
        );
        let duplicate_srv = validate_record_add_constraints(
            &zone,
            &[existing_srv],
            "_sip._tcp",
            &RecordType::SRV,
            "10 5 5060 sip.example.com",
            Some(10),
            None,
        );
        assert!(duplicate_srv.is_err());
    }

    #[test]
    fn validate_delete_constraints_protects_soa_and_primary_ns() {
        let zone = test_zone();

        let soa = test_record(
            1,
            "@",
            RecordType::SOA,
            "ns1.example.com hostmaster.example.com",
            None,
        );
        assert!(validate_delete_constraints(&zone, &[soa]).is_err());

        let primary_ns = test_record(2, "@", RecordType::NS, "ns1.example.com.", None);
        assert!(validate_delete_constraints(&zone, &[primary_ns]).is_err());

        let secondary_ns = test_record(3, "@", RecordType::NS, "ns2.example.com.", None);
        assert!(validate_delete_constraints(&zone, &[secondary_ns]).is_ok());
    }

    fn test_zone() -> Zone {
        Zone {
            id: 1,
            name: "example.com".to_string(),
            primary_ns: "ns1.example.com".to_string(),
            admin_email: "hostmaster@example.com".to_string(),
            ttl: 3600,
            serial: 2023010101,
            refresh: 7200,
            retry: 3600,
            expire: 604800,
            minimum_ttl: 86400,
            created_at: Utc::now(),
        }
    }

    fn test_record(
        id: i32,
        name: &str,
        record_type: RecordType,
        value: &str,
        priority: Option<i32>,
    ) -> Record {
        Record {
            id,
            name: name.to_string(),
            record_type,
            value: value.to_string(),
            ttl: Some(3600),
            priority,
            zone_id: 1,
            created_at: Utc::now(),
        }
    }
}
