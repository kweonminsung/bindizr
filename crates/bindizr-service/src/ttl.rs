//! The TTL rules the API applies. They differ on purpose: a record may carry
//! TTL 0 (RFC 2181, Section 8), a zone's default TTL, which every record
//! without one inherits, stays within a sane range, and an SOA interval of
//! zero would stop secondaries refreshing.

use crate::error::ServiceError;

/// Smallest default TTL a zone may hand out.
const MIN_DEFAULT_TTL: i32 = 60;

/// Largest default TTL a zone may hand out: one week.
const MAX_DEFAULT_TTL: i32 = 604_800;

/// Reject a negative record TTL (RFC 2181, Section 8); the zone's default
/// stands in for an omitted one.
pub(crate) fn validate_record_ttl(ttl: i32) -> Result<(), ServiceError> {
    if ttl < 0 {
        return Err(ServiceError::invalid_input("TTL must not be negative"));
    }
    Ok(())
}

/// Validate a zone's default TTL against the supported range.
pub(crate) fn validate_default_ttl(ttl: i32) -> Result<i32, ServiceError> {
    if ttl < MIN_DEFAULT_TTL {
        return Err(ServiceError::invalid_zone_field(format!(
            "ttl must be at least {} seconds",
            MIN_DEFAULT_TTL
        )));
    }
    if ttl > MAX_DEFAULT_TTL {
        return Err(ServiceError::invalid_zone_field(format!(
            "ttl must be at most {} seconds",
            MAX_DEFAULT_TTL
        )));
    }
    Ok(ttl)
}

/// Resolve an omitted SOA interval to its fallback and require it positive.
pub(crate) fn normalize_soa_interval(
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
