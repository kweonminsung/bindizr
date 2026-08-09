//! Domain-name presentation-form handling: label and length limits, FQDN
//! normalization, containment/apex checks, and the whitespace/control hygiene
//! check shared by name-like inputs.
//!
//! Names here are unescaped: `\` is rejected at every parse boundary, so every
//! `.` is a label boundary and comparisons can split on it. The SOA RNAME is
//! the one escaped name in the system and lives in [`crate::dns::record`].

mod error;
mod owner_name;
mod zone_name;

pub use error::ParseNameError;
pub use owner_name::OwnerName;
pub use zone_name::ZoneName;

/// Maximum length of a single DNS label, in bytes (RFC 1035).
pub(crate) const MAX_DNS_LABEL_LEN: usize = 63;
/// Maximum length of a domain name, in bytes (RFC 1035).
pub(crate) const MAX_DOMAIN_LEN: usize = 253;

/// Whether the value contains any whitespace or ASCII control character.
pub fn has_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
}

/// Classify one label's problem, if any: non-empty, at most 63 bytes, LDH
/// charset (plus `_` when `allow_underscore`), no leading/trailing hyphen.
fn classify_domain_label(label: &str, allow_underscore: bool) -> Result<(), ParseNameError> {
    if label.is_empty() {
        return Err(ParseNameError::EmptyLabel);
    }

    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ParseNameError::LabelTooLong);
    }

    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || (allow_underscore && c == '_'))
    {
        return Err(ParseNameError::LabelCharset {
            underscore_allowed: allow_underscore,
        });
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(ParseNameError::LabelHyphen);
    }

    Ok(())
}

/// [`classify_domain_label`] with the problem phrased against `field`.
pub(crate) fn validate_domain_label(
    label: &str,
    field: &str,
    allow_underscore: bool,
) -> Result<(), String> {
    classify_domain_label(label, allow_underscore).map_err(|e| format!("{} {}", field, e))
}

/// The 253-byte and per-label limits every name must meet on the wire, plus
/// the no-escape rule, without the LDH charset rule that only zone names take.
pub fn classify_wire_labels(name: &str) -> Result<(), ParseNameError> {
    let bare = name.trim_end_matches('.');
    if bare.len() > MAX_DOMAIN_LEN {
        return Err(ParseNameError::TooLong);
    }

    // Rejecting `\` here is what lets every other name comparison split on
    // '.' and be exact: no label can hide a dot that reads as a boundary.
    if bare.contains('\\') {
        return Err(ParseNameError::Escape);
    }

    for label in bare.split('.') {
        if label.is_empty() {
            return Err(ParseNameError::EmptyLabel);
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(ParseNameError::LabelTooLong);
        }
    }

    Ok(())
}

/// Normalize a name to lookup form: trimmed, no trailing dot, lowercase. The
/// LDH rule [`ZoneName::parse`] applies is left out, so `_` labels pass.
pub fn to_lookup_name(value: &str) -> Result<String, ParseNameError> {
    let trimmed = value.trim().trim_end_matches('.');

    if trimmed.is_empty() {
        return Err(ParseNameError::Empty);
    }
    if has_whitespace_or_control(trimmed) {
        return Err(ParseNameError::Whitespace);
    }
    classify_wire_labels(trimmed)?;

    Ok(trimmed.to_ascii_lowercase())
}

/// Return `value` as a lowercase, trailing-dot FQDN.
pub fn to_fqdn_lowercase(value: &str) -> String {
    format!(
        "{}.",
        value.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}

/// Return `value` with a single trailing dot, preserving case.
pub fn to_fqdn(value: &str) -> String {
    format!("{}.", value.trim_end_matches('.'))
}

/// Resolve an owner name to an absolute FQDN within `zone` (`@` = apex; absolute
/// or in-zone names pass through; otherwise `zone` is appended).
pub fn to_owner_fqdn(name: &str, zone: &str) -> String {
    if name.ends_with('.') {
        return name.to_string();
    }

    let zone_trimmed = zone.trim_end_matches('.');
    if name == "@" {
        return format!("{}.", zone_trimmed);
    }

    let owner_trimmed = name.trim_end_matches('.');
    if is_same_or_subdomain_fqdn(
        &owner_trimmed.to_ascii_lowercase(),
        &zone_trimmed.to_ascii_lowercase(),
    ) {
        return format!("{}.", owner_trimmed);
    }

    format!("{}.{}.", owner_trimmed, zone_trimmed)
}

/// [`to_owner_fqdn`] normalized for display: trimmed and lowercased.
pub fn to_display_owner_fqdn(name: &str, zone: &str) -> String {
    to_fqdn_lowercase(&to_owner_fqdn(name.trim(), zone))
}

/// Inverse of [`to_owner_fqdn`]: the relative form record rows encode (`@` at
/// the apex), lowercased to match how lookups bind. `None` when `name` resolves
/// outside `zone`.
pub fn to_encoded_owner_name(name: &str, zone: &str) -> Option<String> {
    let owner = to_owner_fqdn(name, zone).to_ascii_lowercase();
    let zone_fqdn = to_fqdn(zone).to_ascii_lowercase();

    if owner == zone_fqdn {
        return Some("@".to_string());
    }

    let owner_labels: Vec<&str> = owner.split('.').collect();
    let zone_labels: Vec<&str> = zone_fqdn.split('.').collect();
    if owner_labels.len() <= zone_labels.len() || !is_label_suffix(&owner_labels, &zone_labels) {
        return None;
    }

    Some(owner_labels[..owner_labels.len() - zone_labels.len()].join("."))
}

/// Whether `name` equals `zone` or is a subdomain of it, compared label by
/// label so `aexample.com` is not read as inside `example.com`. Both sides
/// must already share the same case and trailing-dot form.
pub fn is_same_or_subdomain_fqdn(name: &str, zone: &str) -> bool {
    is_label_suffix(
        &name.split('.').collect::<Vec<_>>(),
        &zone.split('.').collect::<Vec<_>>(),
    )
}

fn is_label_suffix(name_labels: &[&str], suffix: &[&str]) -> bool {
    name_labels.len() >= suffix.len() && name_labels[name_labels.len() - suffix.len()..] == *suffix
}

/// Whether `name` refers to the zone apex (`@` or the zone name itself).
pub(crate) fn is_apex_name(name: &str, zone_name: &str) -> bool {
    name == "@" || to_fqdn(name).eq_ignore_ascii_case(&to_fqdn(zone_name))
}

#[cfg(test)]
mod tests;
