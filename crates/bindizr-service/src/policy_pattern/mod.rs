//! Record-name-pattern and record-type grant matching, shared by zone TSIG
//! policies (nsupdate) and zone token policies (HTTP API).

use bindizr_core::dns::name::{
    OwnerName, decode_name_labels, has_whitespace_or_control, join_labels,
};

use crate::{error::ServiceError, model::record::RecordType};

/// Pattern/type values granting unrestricted rights.
const MATCH_ANY: &str = "*";

/// Match a relative owner name (`@`, `www`, `a.b`, ...) against a policy
/// pattern: `*` (any name), `@` (apex only), `*.sub` (sub and everything under
/// it), or an exact relative name.
pub(crate) fn pattern_matches_name(pattern: &str, name: &OwnerName) -> bool {
    if pattern == MATCH_ANY {
        return true;
    }

    // Compared label by label so `xsub` does not read as inside `sub`.
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return name.is_same_or_under(&OwnerName::from_row(suffix));
    }

    *name == OwnerName::from_row(pattern)
}

pub(crate) fn types_match(types: &str, record_type: Option<&RecordType>) -> bool {
    if types == MATCH_ANY {
        return true;
    }

    match record_type {
        // A whole-name delete touches every type at the name, so a type-limited
        // policy cannot cover it.
        None => false,
        Some(record_type) => types.split(',').any(|t| t == record_type.as_str()),
    }
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
    let canonical = join_labels(&parse_relative_name(name_part)?);
    Ok(match raw.strip_prefix("*.") {
        Some(_) => format!("*.{}", canonical),
        None => canonical,
    })
}

/// Check a pattern's name part against the pattern grammar, then decode it as
/// a DNS name. Any DNS-level rejection is phrased as a pattern error.
fn parse_relative_name(name: &str) -> Result<Vec<String>, ServiceError> {
    if name.is_empty() {
        return Err(ServiceError::invalid_input(
            "record name pattern must not be empty",
        ));
    }

    if has_whitespace_or_control(name) || name.contains('*') {
        return Err(ServiceError::invalid_input(format!(
            "invalid record name pattern '{}': use '*', '@', '*.<name>' or an exact relative name",
            name
        )));
    }

    // A pattern is a relative owner name, so a trailing dot would leave an
    // empty label that no stored name can match.
    if name.ends_with('.') {
        return Err(ServiceError::invalid_input(
            "record name pattern must not contain empty labels",
        ));
    }

    decode_name_labels(name)
        .map_err(|e| ServiceError::invalid_input(format!("record name pattern {}", e)))
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
        let name = record_type.as_str().to_string();
        if !types.contains(&name) {
            types.push(name);
        }
    }

    Ok(types.join(","))
}

#[cfg(test)]
mod tests;
