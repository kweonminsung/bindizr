//! Authoritative zone matching for the ExternalDNS API.

use bindizr_core::dns::name::{OwnerName, decode_name_labels, is_label_suffix, parse_lookup_name};

use crate::{error::ServiceError, model::zone::Zone};

/// Normalize a request DNS name into zone-lookup form.
pub(crate) fn normalize_lookup_name(name: &str) -> Result<String, ServiceError> {
    parse_lookup_name(name)
        .map_err(|e| ServiceError::invalid_record_name(format!("record name {}", e)))
}

/// Find the most-specific authoritative zone by label boundaries before
/// authorization, so a denied subzone cannot fall back to a granted parent.
pub(crate) fn authoritative_zone<'a>(
    zones: &'a [Zone],
    name: &str,
) -> Option<(&'a Zone, OwnerName)> {
    let (labels, _) = decode_name_labels(name).ok()?;
    let zone = zones
        .iter()
        .filter(|zone| is_label_suffix(&labels, &zone.name.labels()))
        .max_by_key(|zone| zone.name.as_str().len())?;
    let owner = OwnerName::parse_absolute_in_zone(name, &zone.name).ok()?;
    Some((zone, owner))
}
