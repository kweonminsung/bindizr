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
pub use owner_name::{OwnerName, decode_name_labels, is_label_suffix};
pub use zone_name::ZoneName;

/// Maximum length of a single DNS label, in bytes (RFC 1035).
pub const MAX_DNS_LABEL_LEN: usize = 63;
/// Maximum length of a domain name, in bytes (RFC 1035).
pub const MAX_DOMAIN_LEN: usize = 253;

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

/// `classify_domain_label` with the problem phrased against `field`.
pub fn validate_domain_label(
    label: &str,
    field: &str,
    allow_underscore: bool,
) -> Result<(), String> {
    classify_domain_label(label, allow_underscore).map_err(|e| format!("{} {}", field, e))
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

    Ok(join_labels(&decode_name_labels(trimmed)?.0))
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

/// Encode a presentation-form name as uncompressed wire labels, mapping
/// empty/root input to the root name.
pub fn encode_name(name: &str) -> Result<Vec<u8>, String> {
    if name.trim_end_matches('.').is_empty() {
        return Ok(vec![0]);
    }

    let (labels, _) =
        decode_name_labels(name).map_err(|e| format!("Invalid domain name '{}': {}", name, e))?;
    labels_to_wire(labels.iter().map(String::as_str))
        .map_err(|e| format!("Invalid domain name '{}': {}", name, e))
}

/// Length-prefixed wire labels plus the root. Limits are re-checked at this
/// one emitter, so a row edited outside bindizr cannot smuggle a label past
/// the length octet.
pub fn labels_to_wire<'a>(
    labels: impl Iterator<Item = &'a str>,
) -> Result<Vec<u8>, ParseNameError> {
    let mut wire = Vec::new();
    for label in labels {
        if label.is_empty() {
            return Err(ParseNameError::EmptyLabel);
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(ParseNameError::LabelTooLong);
        }
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    if wire.len() > MAX_DOMAIN_LEN + 2 {
        return Err(ParseNameError::TooLong);
    }
    Ok(wire)
}

#[cfg(test)]
mod tests;
