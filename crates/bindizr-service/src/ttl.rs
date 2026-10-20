//! Record TTLs retain explicit values, including zero (RFC 8767, Section 4).
//! Zone defaults follow its one-week cap; SOA intervals and minimums take any
//! unsigned value, zero included (RFC 1035, Section 3.3.13 sets no floor).

use bindizr_core::dns::Ttl;

use crate::error::ServiceError;

/// Smallest default TTL a zone may hand out.
const MIN_DEFAULT_TTL: i64 = 60;

/// Largest default TTL a zone may hand out: one week.
const MAX_DEFAULT_TTL: i64 = 604_800;

/// Validate a record TTL against the unsigned wire range.
pub(crate) fn validate_record_ttl(ttl: i64) -> Result<Ttl, ServiceError> {
    Ttl::try_from(ttl).map_err(ServiceError::invalid_input)
}

/// A zone's default TTL as requested, validated against the supported range.
pub(crate) fn validate_default_ttl(ttl: i64) -> Result<Ttl, ServiceError> {
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
    Ttl::try_from(ttl).map_err(ServiceError::invalid_zone_field)
}

/// Use the fallback for an omitted SOA timer; refuse a negative supplied value.
pub(crate) fn normalize_soa_interval<T: TryFrom<i32>>(
    value: Option<i32>,
    fallback: T,
    field: &str,
) -> Result<T, ServiceError> {
    let Some(secs) = value else {
        return Ok(fallback);
    };
    validate_soa_interval(secs, field)
}

/// Require a supplied SOA interval to be non-negative and representable.
pub(crate) fn validate_soa_interval<T: TryFrom<i32>>(
    secs: i32,
    field: &str,
) -> Result<T, ServiceError> {
    let non_negative = || {
        ServiceError::invalid_zone_field(format!(
            "{} must be a non-negative number of seconds",
            field
        ))
    };
    if secs < 0 {
        return Err(non_negative());
    }
    T::try_from(secs).map_err(|_| non_negative())
}

/// Use the fallback for an omitted minimum TTL; validate supplied values.
pub(crate) fn normalize_minimum_ttl(
    value: Option<i64>,
    fallback: Ttl,
) -> Result<Ttl, ServiceError> {
    value
        .map(validate_minimum_ttl)
        .transpose()
        .map(|ttl| ttl.unwrap_or(fallback))
}

/// Require a SOA negative-cache TTL within the unsigned wire range; zero
/// turns negative caching off (RFC 2308, Section 5).
pub(crate) fn validate_minimum_ttl(value: i64) -> Result<Ttl, ServiceError> {
    if value < 0 {
        return Err(ServiceError::invalid_zone_field(
            "minimum_ttl must be a non-negative number of seconds",
        ));
    }
    Ttl::try_from(value).map_err(ServiceError::invalid_zone_field)
}
