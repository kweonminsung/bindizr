//! Authoritative zone matching for the ExternalDNS API.

use std::collections::HashMap;

use bindizr_core::dns::name;
use bindizr_core::dns::name::OwnerName;
use bindizr_core::model::zone::Zone;

use crate::error::ServiceError;

/// Normalize a request DNS name into zone-lookup form.
pub(crate) fn normalize_lookup_name(name: &str) -> Result<String, ServiceError> {
    name::parse_lookup_name(name)
        .map_err(|error| ServiceError::invalid_record_name(format!("record name {error}")))
}

/// Canonical zone labels indexed for one operation's authoritative-name lookups.
/// Keep hidden zones: a denied child must still shadow its granted parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZoneIndex<'a> {
    zones: HashMap<Vec<Vec<u8>>, &'a Zone>,
}

impl<'a> ZoneIndex<'a> {
    /// Index the supplied rows, whose lock and authorization contract belongs to the flow.
    pub(crate) fn new(zones: &'a [Zone]) -> Self {
        Self {
            zones: zones
                .iter()
                .map(|zone| (zone.name.labels(), zone))
                .collect(),
        }
    }

    /// Find the longest matching label suffix before the caller authorizes the zone.
    pub(crate) fn find(&self, name: &str) -> Option<(&'a Zone, OwnerName)> {
        let (labels, _) = name::decode_name_labels(name).ok()?;
        for start in 0..=labels.len() {
            if let Some(&zone) = self.zones.get(&labels[start..]) {
                let owner = OwnerName::parse_absolute_in_zone(name, &zone.name).ok()?;
                return Some((zone, owner));
            }
        }
        None
    }
}
