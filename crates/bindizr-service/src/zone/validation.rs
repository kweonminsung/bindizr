use crate::{error::ServiceError, types::CreateZoneRequest};
use bindizr_core::dns::name::{
    email_to_soa_mailbox, is_same_or_subdomain_fqdn, split_presentation_labels, to_fqdn_lowercase,
};

const MAX_DOMAIN_LEN: usize = 253;
const MAX_EMAIL_LEN: usize = 254;
const MAX_EMAIL_LOCAL_LEN: usize = 64;
const MAX_DNS_LABEL_LEN: usize = 63;
const MIN_TTL: i32 = 60;
const MAX_TTL: i32 = 604_800;

pub(super) struct ValidatedCreateZoneRequest {
    pub name: String,
    pub name_fqdn: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub ttl: i32,
}

struct NormalizedDomainName {
    storage: String,
    fqdn: String,
}

pub(super) fn validate_create_zone_request(
    request: &CreateZoneRequest,
) -> Result<ValidatedCreateZoneRequest, ServiceError> {
    let zone_name = normalize_zone_name(&request.name)?;
    let primary_ns = normalize_primary_ns(&request.primary_ns)?;
    let admin_email = normalize_email(&request.admin_email)?;
    let ttl = validate_ttl(request.ttl)?;

    if !is_same_or_subdomain_fqdn(&primary_ns.fqdn, &zone_name.fqdn) {
        return Err(ServiceError::BadRequest(
            "primary NS must be in-bailiwick of the zone".to_string(),
        ));
    }

    validate_soa_wire_safety(&zone_name, &primary_ns, &admin_email)?;

    Ok(ValidatedCreateZoneRequest {
        name: zone_name.storage,
        name_fqdn: zone_name.fqdn,
        primary_ns: primary_ns.storage,
        admin_email,
        ttl,
    })
}

pub(super) fn is_same_zone_name(existing_name: &str, normalized_fqdn: &str) -> bool {
    normalize_zone_name(existing_name)
        .map(|existing| existing.fqdn == normalized_fqdn)
        .unwrap_or_else(|_| {
            let existing = to_fqdn_lowercase(existing_name);
            existing == normalized_fqdn
        })
}

pub(super) fn normalize_email(value: &str) -> Result<String, ServiceError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(ServiceError::BadRequest(
            "admin email must not be empty".to_string(),
        ));
    }

    if has_whitespace_or_control(value) {
        return Err(ServiceError::BadRequest(
            "admin email must not contain whitespace or control characters".to_string(),
        ));
    }

    if value.matches('@').count() != 1 {
        return Err(ServiceError::BadRequest(
            "admin email must contain exactly one @".to_string(),
        ));
    }

    let (local, domain) = value
        .split_once('@')
        .expect("admin email contains exactly one @");

    validate_email_local_part(local)?;
    let domain = normalize_domain_name(domain, "admin email domain", false)?;

    let normalized = format!("{}@{}", local, domain.storage);
    if normalized.len() > MAX_EMAIL_LEN {
        return Err(ServiceError::BadRequest(
            "admin email must be 254 bytes or fewer".to_string(),
        ));
    }

    Ok(normalized)
}

fn normalize_zone_name(value: &str) -> Result<NormalizedDomainName, ServiceError> {
    let trimmed = value.trim();

    if trimmed == "." {
        return Err(ServiceError::BadRequest(
            "zone name must not be the root zone".to_string(),
        ));
    }

    if trimmed.starts_with("*.") || trimmed == "*" {
        return Err(ServiceError::BadRequest(
            "wildcard zone names are not allowed".to_string(),
        ));
    }

    normalize_domain_name(trimmed, "zone name", false)
}

fn normalize_primary_ns(value: &str) -> Result<NormalizedDomainName, ServiceError> {
    normalize_domain_name(value, "primary NS", false)
}

fn normalize_domain_name(
    value: &str,
    field: &str,
    allow_wildcard: bool,
) -> Result<NormalizedDomainName, ServiceError> {
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
            "{} must not be empty",
            field
        )));
    }

    if without_trailing_dot.len() > MAX_DOMAIN_LEN {
        return Err(ServiceError::BadRequest(format!(
            "{} must be 253 bytes or fewer",
            field
        )));
    }

    for label in without_trailing_dot.split('.') {
        validate_domain_label(label, field, allow_wildcard)?;
    }

    let storage = without_trailing_dot.to_ascii_lowercase();
    let fqdn = format!("{}.", storage);

    Ok(NormalizedDomainName { storage, fqdn })
}

fn validate_domain_label(
    label: &str,
    field: &str,
    allow_wildcard: bool,
) -> Result<(), ServiceError> {
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

    if label == "*" {
        if allow_wildcard {
            return Ok(());
        }

        return Err(ServiceError::BadRequest(format!(
            "{} must not contain wildcard labels",
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

fn validate_email_local_part(local: &str) -> Result<(), ServiceError> {
    if local.is_empty() {
        return Err(ServiceError::BadRequest(
            "admin email local part must not be empty".to_string(),
        ));
    }

    if local.len() > MAX_EMAIL_LOCAL_LEN {
        return Err(ServiceError::BadRequest(
            "admin email local part must be 64 bytes or fewer".to_string(),
        ));
    }

    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(ServiceError::BadRequest(
            "admin email local part must not start, end, or contain consecutive dots".to_string(),
        ));
    }

    if !local.chars().all(is_valid_email_local_char) {
        return Err(ServiceError::BadRequest(
            "admin email local part contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_ttl(ttl: i32) -> Result<i32, ServiceError> {
    if ttl < MIN_TTL {
        return Err(ServiceError::BadRequest(format!(
            "ttl must be at least {} seconds",
            MIN_TTL
        )));
    }

    if ttl > MAX_TTL {
        return Err(ServiceError::BadRequest(format!(
            "ttl must be at most {} seconds",
            MAX_TTL
        )));
    }

    Ok(ttl)
}

fn validate_soa_wire_safety(
    zone_name: &NormalizedDomainName,
    primary_ns: &NormalizedDomainName,
    admin_email: &str,
) -> Result<(), ServiceError> {
    validate_wire_domain_name(&zone_name.fqdn, "zone name")?;
    validate_wire_domain_name(&primary_ns.fqdn, "primary NS")?;
    let soa_mailbox =
        email_to_soa_mailbox(admin_email).map_err(|e| ServiceError::BadRequest(e.to_string()))?;
    validate_wire_domain_name(&soa_mailbox, "admin email SOA RNAME")?;
    Ok(())
}

fn validate_wire_domain_name(name: &str, field: &str) -> Result<(), ServiceError> {
    let name = name.trim_end_matches('.');

    if name.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must be wire-encodable",
            field
        )));
    }

    for label in
        split_presentation_labels(name).map_err(|e| ServiceError::BadRequest(e.to_string()))?
    {
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
    }

    Ok(())
}

fn has_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
}

fn is_valid_email_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
                | '.'
        )
}
