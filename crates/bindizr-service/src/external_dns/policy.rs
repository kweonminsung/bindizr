//! Authoritative zone matching for the ExternalDNS API.

use crate::{
    error::ServiceError,
    model::zone::Zone,
    validation::{has_whitespace_or_control, validate_wire_labels},
};

/// Normalize a request DNS name into zone-lookup form: trimmed, lowercase, no
/// trailing dot.
pub(super) fn normalize_lookup_name(name: &str) -> Result<String, ServiceError> {
    let trimmed = name.trim().trim_end_matches('.');

    if trimmed.is_empty() {
        return Err(ServiceError::invalid_record_name(
            "record name must not be empty".to_string(),
        ));
    }
    if has_whitespace_or_control(trimmed) {
        return Err(ServiceError::invalid_record_name(
            "record name must not contain whitespace or control characters".to_string(),
        ));
    }
    validate_wire_labels(trimmed, "record name")?;

    Ok(trimmed.to_ascii_lowercase())
}

/// Most-specific existing zone authoritative for `name` (lookup form),
/// honoring DNS label boundaries. Matching runs over all zones before any
/// authorization, so a name in a denied subzone never falls back to a
/// granted parent zone.
pub(super) fn find_authoritative_zone<'a>(zones: &'a [Zone], name: &str) -> Option<&'a Zone> {
    zones
        .iter()
        .filter(|zone| name == zone.name || name.ends_with(&format!(".{}", zone.name)))
        .max_by_key(|zone| zone.name.len())
}

/// Stored (relative) owner name for `name` inside `zone`: `@` at the apex.
/// `name` must already be inside the zone in lookup form.
pub(super) fn stored_owner_name(name: &str, zone: &Zone) -> String {
    if name == zone.name {
        "@".to_string()
    } else {
        name[..name.len() - zone.name.len() - 1].to_string()
    }
}
