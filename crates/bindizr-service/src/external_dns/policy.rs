//! Authoritative zone matching for the ExternalDNS API.

use bindizr_core::dns::name::{decode_name_labels, is_label_suffix, to_lookup_name};

use crate::{error::ServiceError, model::zone::Zone};

/// Normalize a request DNS name into zone-lookup form.
pub(crate) fn normalize_lookup_name(name: &str) -> Result<String, ServiceError> {
    to_lookup_name(name)
        .map_err(|e| ServiceError::invalid_record_name(format!("record name {}", e)))
}

/// Most-specific existing zone authoritative for `name` (lookup form),
/// honoring DNS label boundaries. Matching runs over all zones before any
/// authorization, so a name in a denied subzone never falls back to a
/// granted parent zone.
pub(crate) fn find_authoritative_zone<'a>(zones: &'a [Zone], name: &str) -> Option<&'a Zone> {
    let (labels, _) = decode_name_labels(name).ok()?;
    zones
        .iter()
        .filter(|zone| is_label_suffix(&labels, &zone.name.labels()))
        .max_by_key(|zone| zone.name.as_str().len())
}
