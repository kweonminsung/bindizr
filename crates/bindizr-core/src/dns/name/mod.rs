//! Parse and normalize names, enforcing label, length, and whitespace limits.
//! [`OwnerName`] and [`ZoneName`] decode labels before comparison: escaped dots
//! remain label data. Text uses canonical RFC 1035, Section 5.1 escapes.

mod error;
mod owner_name;
mod zone_name;

pub use error::{EncodeNameError, ParseNameError};
pub use owner_name::{OwnerName, decode_name_labels, is_label_suffix};
pub use zone_name::ZoneName;

/// Maximum length of a single DNS label, in bytes (RFC 1035).
pub(crate) const MAX_DNS_LABEL_LEN: usize = 63;
/// Maximum unescaped presentation length, excluding the root dot.
/// The wire form adds a label-length octet and the terminating zero.
pub(crate) const MAX_DOMAIN_LEN: usize = 253;

/// Check whether text contains whitespace or control characters.
pub fn has_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
}

/// Classify one label's problem, if any: non-empty, at most 63 bytes, LDH
/// charset (plus `_` when `LabelCharset::LdhUnderscore`), no leading/trailing hyphen.
pub(crate) fn classify_domain_label(
    label: &str,
    charset: LabelCharset,
) -> Result<(), ParseNameError> {
    if label.is_empty() {
        return Err(ParseNameError::EmptyLabel);
    }

    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ParseNameError::LabelTooLong);
    }

    if !label.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '-'
            || (charset == LabelCharset::LdhUnderscore && c == '_')
    }) {
        return Err(ParseNameError::LabelCharset {
            underscore_allowed: charset == LabelCharset::LdhUnderscore,
        });
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(ParseNameError::LabelHyphen);
    }

    Ok(())
}

/// Normalize a name to lookup form: trimmed, no trailing dot, lowercase, and
/// re-escaped canonically so two spellings of one name compare equal as text.
pub fn parse_lookup_name(value: &str) -> Result<String, ParseNameError> {
    let trimmed = value.trim();

    if trimmed.trim_end_matches('.').is_empty() {
        return Err(ParseNameError::Empty);
    }
    if has_whitespace_or_control(trimmed) {
        return Err(ParseNameError::Whitespace);
    }

    Ok(labels_to_presentation(&decode_name_labels(trimmed)?.0))
}

/// Convert decoded labels back to presentation form.
pub fn labels_to_presentation(labels: &[String]) -> String {
    // Most owners are one label, which needs no join buffer.
    if let [label] = labels {
        return owner_name::escape_label(label).into_owned();
    }
    labels
        .iter()
        .map(|label| owner_name::escape_label(label))
        .collect::<Vec<_>>()
        .join(".")
}

/// Return `value` as a lowercase, trailing-dot FQDN: labels decoded and
/// re-escaped canonically, so a `\.` stays inside its label. A value that does
/// not decode keeps its own spelling — this renders, it does not validate.
pub(crate) fn to_fqdn_lowercase(value: &str) -> String {
    let trimmed = value.trim();
    // LDH and underscore labels need no escaping, so this fast path
    // produces the same lowercase form as decoding and re-encoding.
    let needs_decode = trimmed
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')));
    if needs_decode && let Ok(name) = parse_lookup_name(trimmed) {
        return format!("{name}.");
    }
    format!("{}.", trimmed.trim_end_matches('.').to_ascii_lowercase())
}

/// Return `value` with a single trailing dot, preserving case. Only the one
/// root dot is stripped, so an escaped trailing dot inside the last label
/// stays data.
pub fn to_fqdn(value: &str) -> String {
    format!("{}.", value.strip_suffix('.').unwrap_or(value))
}

/// Encode a presentation-form name as uncompressed wire labels, mapping
/// empty/root input to the root name.
pub fn encode_name(name: &str) -> Result<Vec<u8>, EncodeNameError> {
    if name.trim_end_matches('.').is_empty() {
        return Ok(vec![0]);
    }

    let failed = |source| EncodeNameError {
        name: name.to_string(),
        source,
    };
    let (labels, _) = decode_name_labels(name).map_err(failed)?;
    labels_to_wire(labels.iter().map(String::as_str)).map_err(failed)
}

/// Encode length-prefixed labels and the root, rechecking wire limits
/// because stored rows may have been edited outside bindizr.
fn labels_to_wire<'a>(labels: impl Iterator<Item = &'a str>) -> Result<Vec<u8>, ParseNameError> {
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

/// Character policy for an LDH label validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LabelCharset {
    Ldh,
    LdhUnderscore,
}
