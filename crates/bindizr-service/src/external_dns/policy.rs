//! Authoritative zone matching for the ExternalDNS API.

use bindizr_core::dns::name;
use bindizr_core::dns::name::OwnerName;

use crate::error::ServiceError;
use crate::model::zone::Zone;

/// Normalize a request DNS name into zone-lookup form.
pub(crate) fn normalize_lookup_name(name: &str) -> Result<String, ServiceError> {
    name::parse_lookup_name(name)
        .map_err(|error| ServiceError::invalid_record_name(format!("record name {}", error)))
}

/// Find the most-specific authoritative zone by label boundaries before
/// authorization, so a denied subzone cannot fall back to a granted parent.
pub(crate) fn authoritative_zone<'a>(
    zones: &'a [Zone],
    name: &str,
) -> Option<(&'a Zone, OwnerName)> {
    let (labels, _) = name::decode_name_labels(name).ok()?;
    let zone = zones
        .iter()
        .filter(|zone| name::is_label_suffix(&labels, &zone.name.labels()))
        .max_by_key(|zone| zone.name.as_str().len())?;
    let owner = OwnerName::parse_absolute_in_zone(name, &zone.name).ok()?;

    Some((zone, owner))
}
