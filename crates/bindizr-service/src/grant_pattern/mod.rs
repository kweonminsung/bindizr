//! Normalize grant name patterns and type lists and derive their covered domains.
//! Core's `grant_pattern` owns matching.

use bindizr_core::dns::name;
use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::model::grant_pattern::MATCH_ANY;

use crate::error::ServiceError;
use crate::model::record::RecordType;

/// Derive an ExternalDNS domain filter, which includes all descendants.
/// Widen `@` and exact names to their containing domain.
pub(crate) fn pattern_domain(pattern: &str, zone_name: &ZoneName) -> String {
    if pattern == MATCH_ANY || pattern == OwnerName::APEX {
        return zone_name.to_fqdn();
    }
    let name = pattern.strip_prefix("*.").unwrap_or(pattern);
    OwnerName::from_row(name).to_fqdn(zone_name)
}

/// Normalize and validate a record name pattern; `None` grants all names.
pub(crate) fn normalize_pattern(value: Option<&str>) -> Result<String, ServiceError> {
    let raw = match value.map(str::trim) {
        None | Some("") => return Ok(MATCH_ANY.to_string()),
        Some(raw) => raw,
    };

    if raw == MATCH_ANY || raw == OwnerName::APEX {
        return Ok(raw.to_string());
    }

    let name_part = raw.strip_prefix("*.").unwrap_or(raw);

    // Store the canonical spelling so one name is one pattern.
    let canonical = name::labels_to_presentation(&parse_relative_name(name_part)?);

    Ok(match raw.strip_prefix("*.") {
        Some(_) => format!("*.{}", canonical),
        None => canonical,
    })
}

/// Decode a pattern's name part and hold it to the pattern grammar; the name
/// rules themselves (empty, length, charset) come with decoding.
fn parse_relative_name(name: &str) -> Result<Vec<Vec<u8>>, ServiceError> {
    let (labels, rooted) = name::decode_name_labels(name)
        .map_err(|error| ServiceError::invalid_input(format!("record name pattern {}", error)))?;

    // A pattern is relative, and `*` is the language's metacharacter: it is
    // not escaped on render, so a label spelled `\042` would read as a grant.
    if rooted || labels.iter().any(|label| label.contains(&b'*')) {
        return Err(ServiceError::invalid_input(format!(
            "invalid record name pattern '{}': use '*', '@', '*.<name>' or an exact relative name",
            name
        )));
    }

    Ok(labels)
}

/// Normalize and validate a record type list; `None` grants all types.
pub(crate) fn normalize_types(value: Option<&str>) -> Result<String, ServiceError> {
    let raw = match value.map(str::trim) {
        None | Some("") => return Ok(MATCH_ANY.to_string()),
        Some(raw) => raw,
    };

    if raw == MATCH_ANY {
        return Ok(MATCH_ANY.to_string());
    }

    let mut types: Vec<String> = Vec::new();

    for part in raw.split(',') {
        let record_type: RecordType = part.trim().parse().map_err(ServiceError::invalid_input)?;
        let name = record_type.as_str().to_owned();
        if !types.contains(&name) {
            types.push(name);
        }
    }

    Ok(types.join(","))
}

#[cfg(test)]
mod tests;
