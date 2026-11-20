//! Normalize grant name patterns and type lists and derive their covered domains.
//! Core's `grant_pattern` owns matching.

use bindizr_core::dns::name;
use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::model::grant_pattern::MATCH_ANY;

use crate::error::ServiceError;
use crate::record;

/// Derive an ExternalDNS domain filter, which includes all descendants.
/// Widen `@` and exact names to their containing domain.
pub(crate) fn pattern_domain(pattern: &str, zone_name: &ZoneName) -> String {
    if pattern == MATCH_ANY || pattern == OwnerName::APEX {
        return zone_name.to_fqdn();
    }
    let name_part = pattern.strip_prefix("*.").unwrap_or(pattern);
    OwnerName::from_row(name_part).to_fqdn(zone_name)
}

/// Normalize and validate a record name pattern; `None` grants all names.
pub(crate) fn normalize_pattern(value: Option<&str>) -> Result<String, ServiceError> {
    let Some(raw) = value.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(MATCH_ANY.to_string());
    };

    if raw == MATCH_ANY || raw == OwnerName::APEX {
        return Ok(raw.to_string());
    }

    let name_part = raw.strip_prefix("*.").unwrap_or(raw);

    // Store the canonical spelling so one name is one pattern.
    let canonical = name::labels_to_presentation(&parse_relative_name(name_part)?);

    Ok(if raw.starts_with("*.") {
        format!("*.{canonical}")
    } else {
        canonical
    })
}

/// Decode a pattern's name part and hold it to the pattern grammar; the name
/// rules themselves (empty, length, charset) come with decoding.
fn parse_relative_name(name: &str) -> Result<Vec<Vec<u8>>, ServiceError> {
    let (labels, rooted) = name::decode_name_labels(name)
        .map_err(|error| ServiceError::invalid_input(format!("record name pattern {error}")))?;

    // A pattern is relative, and `*` is the language's metacharacter: it is
    // not escaped on render, so a label spelled `\042` would read as a grant.
    if rooted || labels.iter().any(|label| label.contains(&b'*')) {
        return Err(ServiceError::invalid_input(format!(
            "invalid record name pattern '{name}': use '*', '@', '*.<name>' or an exact relative name"
        )));
    }

    Ok(labels)
}

/// Normalize and validate a record type list; `None` grants all types.
pub(crate) fn normalize_types(value: Option<&str>) -> Result<String, ServiceError> {
    let Some(raw) = value.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(MATCH_ANY.to_string());
    };

    if raw == MATCH_ANY {
        return Ok(MATCH_ANY.to_string());
    }

    let mut types: Vec<String> = Vec::new();

    for part in raw.split(',') {
        let record_type = record::parse_record_type(part.trim())?;
        let name = record_type.to_string();
        if !types.contains(&name) {
            types.push(name);
        }
    }

    Ok(types.join(","))
}

#[cfg(test)]
mod tests;
