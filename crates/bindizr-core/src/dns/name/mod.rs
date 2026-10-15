//! Parse DNS octet labels and render canonical RFC 1035, Section 5.1 escapes.
//! [`OwnerName`] and [`ZoneName`] compare decoded labels, preserving escaped dots.

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
/// hostname charset including underscores, without a leading/trailing hyphen.
pub(crate) fn classify_domain_label(label: &str) -> Result<(), ParseNameError> {
    if label.is_empty() {
        return Err(ParseNameError::EmptyLabel);
    }

    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ParseNameError::LabelTooLong);
    }

    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ParseNameError::LabelCharset {
            underscore_allowed: true,
        });
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(ParseNameError::LabelHyphen);
    }

    Ok(())
}

/// Trim surrounding input whitespace without eating a final escaped label octet.
pub(crate) fn trim_presentation_name(value: &str) -> &str {
    let mut value = value.trim_start();
    while let Some(last) = value.chars().next_back().filter(|c| c.is_whitespace()) {
        let prefix = &value[..value.len() - last.len_utf8()];
        if prefix.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 1 {
            break;
        }
        value = prefix;
    }
    value
}

/// Normalize a name to lookup form: trimmed, no trailing dot, lowercase, and
/// re-escaped canonically so two spellings of one name compare equal as text.
pub fn parse_lookup_name(value: &str) -> Result<String, ParseNameError> {
    let trimmed = trim_presentation_name(value);

    if trimmed.trim_end_matches('.').is_empty() {
        return Err(ParseNameError::Empty);
    }

    Ok(labels_to_presentation(&decode_name_labels(trimmed)?.0))
}

/// Convert decoded labels back to presentation form.
pub fn labels_to_presentation(labels: &[impl AsRef<[u8]>]) -> String {
    // Most owners are one label, which needs no join buffer.
    if let [label] = labels {
        return owner_name::escape_label(label.as_ref());
    }
    labels
        .iter()
        .map(|label| owner_name::escape_label(label.as_ref()))
        .collect::<Vec<_>>()
        .join(".")
}

/// Render a lowercase FQDN with canonical escapes, preserving in-label dots.
/// Undecodable input keeps its spelling; this function does not validate.
pub(crate) fn to_fqdn_lowercase(value: &str) -> String {
    let trimmed = trim_presentation_name(value);
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

/// Append one root dot, preserving case and escaped dots within labels.
pub fn to_fqdn(value: &str) -> String {
    if value == "." {
        return value.to_string();
    }
    match owner_name::decode_preserved_labels(value) {
        Ok((labels, _)) => format!("{}.", labels_to_presentation(&labels)),
        Err(_) => format!("{}.", value.strip_suffix('.').unwrap_or(value)),
    }
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
    let (labels, _) = owner_name::decode_preserved_labels(name).map_err(failed)?;
    labels_to_wire(labels.iter().map(Vec::as_slice)).map_err(failed)
}

/// Encode length-prefixed labels and the root, rechecking wire limits
/// because stored rows may have been edited outside bindizr.
fn labels_to_wire<'a>(labels: impl Iterator<Item = &'a [u8]>) -> Result<Vec<u8>, ParseNameError> {
    let mut wire = Vec::new();
    for label in labels {
        if label.is_empty() {
            return Err(ParseNameError::EmptyLabel);
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(ParseNameError::LabelTooLong);
        }
        wire.push(label.len() as u8);
        wire.extend_from_slice(label);
    }
    wire.push(0);
    if wire.len() > MAX_DOMAIN_LEN + 2 {
        return Err(ParseNameError::TooLong);
    }
    Ok(wire)
}

#[cfg(test)]
mod tests;
