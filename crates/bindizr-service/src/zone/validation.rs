use bindizr_core::dns::{
    name::{ZoneName, has_whitespace_or_control},
    record::SoaMailbox,
};

use crate::{error::ServiceError, types::CreateZoneRequest};

const MAX_EMAIL_LEN: usize = 254;
const MAX_EMAIL_LOCAL_LEN: usize = 64;
const MIN_TTL: i32 = 60;
const MAX_TTL: i32 = 604_800;

pub(crate) struct ValidatedCreateZoneRequest {
    pub(crate) name: ZoneName,
    pub(crate) mname: String,
    pub(crate) rname: String,
    pub(crate) ttl: i32,
}

pub(crate) fn validate_create_zone_request(
    request: &CreateZoneRequest,
) -> Result<ValidatedCreateZoneRequest, ServiceError> {
    let zone_name = normalize_zone_name(&request.name)?;
    let mname = normalize_domain_name(&request.mname, "mname")?.to_string();
    let rname = normalize_email(&request.rname)?;
    let ttl = validate_ttl(request.default_ttl)?;

    validate_soa_wire_safety(&rname)?;

    Ok(ValidatedCreateZoneRequest {
        name: zone_name,
        mname,
        rname,
        ttl,
    })
}

pub(crate) fn normalize_zone_name(value: &str) -> Result<ZoneName, ServiceError> {
    let trimmed = value.trim();

    if trimmed == "." {
        return Err(ServiceError::invalid_zone_field(
            "zone name must not be the root zone".to_string(),
        ));
    }

    if trimmed.starts_with("*.") || trimmed == "*" {
        return Err(ServiceError::invalid_zone_field(
            "wildcard zone names are not allowed".to_string(),
        ));
    }

    normalize_domain_name(trimmed, "zone name")
}

/// Parse a domain name, phrasing any rejection against `field`. The rules
/// live on [`ZoneName`]; this only maps the failure to a zone error.
fn normalize_domain_name(value: &str, field: &str) -> Result<ZoneName, ServiceError> {
    ZoneName::parse(value).map_err(|e| ServiceError::invalid_zone_field(format!("{} {}", field, e)))
}

fn normalize_email(value: &str) -> Result<String, ServiceError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(ServiceError::invalid_zone_field(
            "rname must not be empty".to_string(),
        ));
    }

    if has_whitespace_or_control(value) {
        return Err(ServiceError::invalid_zone_field(
            "rname must not contain whitespace or control characters".to_string(),
        ));
    }

    if value.matches('@').count() != 1 {
        return Err(ServiceError::invalid_zone_field(
            "rname must contain exactly one @".to_string(),
        ));
    }

    let (local, domain) = value.split_once('@').expect("rname contains exactly one @");

    validate_email_local_part(local)?;
    let domain = normalize_domain_name(domain, "rname domain")?;

    let normalized = format!("{}@{}", local, domain);
    if normalized.len() > MAX_EMAIL_LEN {
        return Err(ServiceError::invalid_zone_field(
            "rname must be 254 bytes or fewer".to_string(),
        ));
    }

    Ok(normalized)
}

fn validate_email_local_part(local: &str) -> Result<(), ServiceError> {
    if local.is_empty() {
        return Err(ServiceError::invalid_zone_field(
            "rname local part must not be empty".to_string(),
        ));
    }

    if local.len() > MAX_EMAIL_LOCAL_LEN {
        return Err(ServiceError::invalid_zone_field(
            "rname local part must be 64 bytes or fewer".to_string(),
        ));
    }

    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(ServiceError::invalid_zone_field(
            "rname local part must not start, end, or contain consecutive dots".to_string(),
        ));
    }

    if !local.chars().all(is_valid_email_local_char) {
        return Err(ServiceError::invalid_zone_field(
            "rname local part contains invalid characters".to_string(),
        ));
    }

    Ok(())
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

fn validate_ttl(ttl: i32) -> Result<i32, ServiceError> {
    if ttl < MIN_TTL {
        return Err(ServiceError::invalid_zone_field(format!(
            "ttl must be at least {} seconds",
            MIN_TTL
        )));
    }

    if ttl > MAX_TTL {
        return Err(ServiceError::invalid_zone_field(format!(
            "ttl must be at most {} seconds",
            MAX_TTL
        )));
    }

    Ok(ttl)
}

/// Resolved SOA timing fields. Used both as the fallback source (zone defaults on
/// create, the existing zone's values on update) and as the validated output.
pub(crate) struct ResolvedSoaTimers {
    pub(crate) refresh: i32,
    pub(crate) retry: i32,
    pub(crate) expire: i32,
    pub(crate) minimum_ttl: i32,
}

/// Validate client-supplied SOA timers, using `fallback` for omitted fields
/// (zone defaults on create, the existing zone's values on update).
pub(crate) fn resolve_soa_timers(
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
        return Err(ServiceError::invalid_zone_field(format!(
            "{} must be a positive number of seconds",
            field
        )));
    }
    Ok(resolved)
}

// `zone_name` and `mname` are already wire-safe after `normalize_domain_name`
// (plain ASCII labels, each <= 63 bytes); the derived SOA RNAME's shifted
// label boundaries are checked by `SoaMailbox::from_email` itself.
fn validate_soa_wire_safety(rname: &str) -> Result<(), ServiceError> {
    SoaMailbox::from_email(rname)
        .map(|_| ())
        .map_err(|e| ServiceError::invalid_zone_field(format!("rname {}", e)))
}
