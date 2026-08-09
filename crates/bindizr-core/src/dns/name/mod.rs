//! Domain-name handling: label and length limits, FQDN normalization, and the
//! whitespace/control hygiene check shared by name-like inputs.
//!
//! Names decode into labels at the parse boundary ([`OwnerName`], [`ZoneName`]),
//! so an escaped dot is label data and never a boundary. Text is a rendering,
//! re-escaped canonically (RFC 1035, Section 5.1).

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

/// Decode a name into its labels, applying the 253-byte and per-label limits
/// but not the LDH charset rule that only zone names take.
pub fn decode_name_labels(name: &str) -> Result<Vec<String>, ParseNameError> {
    owner_name::decode_checked(name).map(|(labels, _)| labels)
}

/// Normalize a name to lookup form: trimmed, no trailing dot, lowercase, and
/// re-escaped canonically so two spellings of one name compare equal as text.
pub fn to_lookup_name(value: &str) -> Result<String, ParseNameError> {
    let trimmed = value.trim();

    if trimmed.trim_end_matches('.').is_empty() {
        return Err(ParseNameError::Empty);
    }
    if has_whitespace_or_control(trimmed) {
        return Err(ParseNameError::Whitespace);
    }

    Ok(join_labels(&decode_name_labels(trimmed)?))
}

/// Whether a decoded name sits at or under `zone`'s labels.
pub fn labels_in_zone(name: &[String], zone: &[String]) -> bool {
    owner_name::is_label_suffix(name, zone)
}

/// Render decoded labels back to presentation form.
pub fn join_labels(labels: &[String]) -> String {
    labels
        .iter()
        .map(|label| owner_name::escape_label(label))
        .collect::<Vec<_>>()
        .join(".")
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

#[cfg(test)]
mod tests;
