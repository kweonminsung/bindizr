//! Normalize grant name patterns and type lists and derive their covered domains.
//! Core's `grant_pattern` owns the name grammar and matching.

use bindizr_core::dns::name::{OwnerName, ParseNameError, ZoneName};
use bindizr_core::model::grant_pattern::{MATCH_ANY, ParsePatternOwnerError, parse_pattern_owner};

use crate::error::ServiceError;
use crate::record;

/// Derive a domain filter, which includes the name and all its descendants.
/// Skip patterns whose root is already too long to be an owner in this zone.
pub(crate) fn pattern_domain(
    pattern: &str,
    zone_name: &ZoneName,
) -> Result<Option<String>, ServiceError> {
    if pattern == MATCH_ANY || pattern == OwnerName::APEX {
        return Ok(Some(zone_name.to_string()));
    }

    let name_part = pattern.strip_prefix("*.").unwrap_or(pattern);
    let owner = parse_pattern_owner(name_part).map_err(|source| {
        ServiceError::internal_with_source("invalid stored record name pattern", source)
    })?;

    match owner.to_wire(zone_name) {
        Ok(_) => Ok(Some(format!("{owner}.{zone_name}"))),
        Err(ParseNameError::TooLong) => Ok(None),
        Err(source) => Err(ServiceError::internal_with_source(
            "invalid domain for stored record name pattern",
            source,
        )),
    }
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

    let owner = parse_pattern_owner(name_part).map_err(|source| {
        let message = match source {
            ParsePatternOwnerError::Name(ParseNameError::Absolute)
            | ParsePatternOwnerError::Wildcard => format!(
                "invalid record name pattern '{name_part}': use '*', '@', '*.<name>' or an exact relative name"
            ),
            ParsePatternOwnerError::Name(error) => format!("record name pattern {error}"),
        };
        ServiceError::invalid_input_with_source(message, source)
    })?;

    Ok(if raw.starts_with("*.") {
        format!("*.{owner}")
    } else {
        owner.to_string()
    })
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
