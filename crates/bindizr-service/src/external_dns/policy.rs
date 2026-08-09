//! Authoritative zone matching for the ExternalDNS API.

use bindizr_core::dns::name::to_lookup_name;

use crate::{error::ServiceError, model::zone::Zone};

/// Normalize a request DNS name into zone-lookup form.
pub(super) fn normalize_lookup_name(name: &str) -> Result<String, ServiceError> {
    to_lookup_name(name)
        .map_err(|e| ServiceError::invalid_record_name(format!("record name {}", e)))
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
