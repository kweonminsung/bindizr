use bindizr_core::dns::name::email_to_soa_mailbox;

use crate::{
    error::ServiceError,
    types::CreateZoneRequest,
    validation::{
        MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN, has_whitespace_or_control, validate_wire_labels,
    },
};

const MAX_EMAIL_LEN: usize = 254;
const MAX_EMAIL_LOCAL_LEN: usize = 64;
const MIN_TTL: i32 = 60;
const MAX_TTL: i32 = 604_800;

pub(super) struct ValidatedCreateZoneRequest {
    pub name: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub ttl: i32,
}

/// Resolved SOA timing fields. Used both as the fallback source (zone defaults on
/// create, the existing zone's values on update) and as the validated output.
pub(super) struct ResolvedSoaTimers {
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum_ttl: i32,
}

/// Validate client-supplied SOA timers, using `fallback` for omitted fields
/// (zone defaults on create, the existing zone's values on update).
pub(super) fn resolve_soa_timers(
    request: &CreateZoneRequest,
    fallback: ResolvedSoaTimers,
) -> Result<ResolvedSoaTimers, ServiceError> {
    Ok(ResolvedSoaTimers {
        refresh: resolve_soa_interval(request.refresh, fallback.refresh, "refresh")?,
        retry: resolve_soa_interval(request.retry, fallback.retry, "retry")?,
        expire: resolve_soa_interval(request.expire, fallback.expire, "expire")?,
        minimum_ttl: resolve_soa_interval(
            request.minimum_ttl,
            fallback.minimum_ttl,
            "minimum_ttl",
        )?,
    })
}

fn resolve_soa_interval(
    value: Option<i32>,
    fallback: i32,
    field: &str,
) -> Result<i32, ServiceError> {
    let resolved = value.unwrap_or(fallback);
    if resolved <= 0 {
        return Err(ServiceError::BadRequest(format!(
            "{} must be a positive number of seconds",
            field
        )));
    }
    Ok(resolved)
}

pub(super) fn validate_create_zone_request(
    request: &CreateZoneRequest,
) -> Result<ValidatedCreateZoneRequest, ServiceError> {
    let zone_name = normalize_zone_name(&request.name)?;
    let primary_ns = normalize_primary_ns(&request.primary_ns)?;
    let admin_email = normalize_email(&request.admin_email)?;
    let ttl = validate_ttl(request.ttl)?;

    validate_soa_wire_safety(&admin_email)?;

    Ok(ValidatedCreateZoneRequest {
        name: zone_name,
        primary_ns,
        admin_email,
        ttl,
    })
}

fn normalize_email(value: &str) -> Result<String, ServiceError> {
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
    let domain = normalize_domain_name(domain, "admin email domain")?;

    let normalized = format!("{}@{}", local, domain);
    if normalized.len() > MAX_EMAIL_LEN {
        return Err(ServiceError::BadRequest(
            "admin email must be 254 bytes or fewer".to_string(),
        ));
    }

    Ok(normalized)
}

pub(crate) fn normalize_zone_name(value: &str) -> Result<String, ServiceError> {
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

    normalize_domain_name(trimmed, "zone name")
}

fn normalize_primary_ns(value: &str) -> Result<String, ServiceError> {
    normalize_domain_name(value, "primary NS")
}

fn normalize_domain_name(value: &str, field: &str) -> Result<String, ServiceError> {
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
        validate_domain_label(label, field)?;
    }

    Ok(without_trailing_dot.to_ascii_lowercase())
}

fn validate_domain_label(label: &str, field: &str) -> Result<(), ServiceError> {
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

// `zone_name` and `primary_ns` are already wire-safe after `normalize_domain_name`
// (plain ASCII labels, each <= 63 bytes), so only the derived SOA RNAME, whose
// label boundaries can shift during the email-to-mailbox escaping, needs rechecking.
fn validate_soa_wire_safety(admin_email: &str) -> Result<(), ServiceError> {
    let soa_mailbox =
        email_to_soa_mailbox(admin_email).map_err(|e| ServiceError::BadRequest(e.to_string()))?;
    validate_wire_labels(&soa_mailbox, "admin email SOA RNAME")
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
