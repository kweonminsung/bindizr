//! Parse DNS octet labels and render canonical RFC 1035, Section 5.1 escapes.
//! [`OwnerName`] and [`ZoneName`] compare decoded labels, preserving escaped dots.

mod error;
mod owner_name;
mod zone_name;

use std::mem;

use domain::base::Name;
pub use error::{EncodeNameError, EncodeWireNameError, ParseNameError};
pub use owner_name::OwnerName;
pub use zone_name::ZoneName;

/// The name form the `domain` crate takes, for messages and DNSSEC alike.
pub type WireName = Name<Vec<u8>>;

/// Maximum length of a single DNS label, in bytes (RFC 1035).
pub(crate) const MAX_DNS_LABEL_LEN: usize = 63;

/// Maximum encoded name length, including the terminating root label (RFC 1035).
pub(crate) const MAX_WIRE_NAME_LEN: usize = 255;

/// Maximum unescaped presentation length, excluding the root dot.
/// The wire form adds a label-length octet and the terminating zero.
pub(crate) const MAX_DOMAIN_LEN: usize = MAX_WIRE_NAME_LEN - 2;

/// Trim surrounding input whitespace without eating a final escaped label octet.
pub fn trim_presentation_name(value: &str) -> &str {
    let mut value = value.trim_start();

    while let Some(last) = value.chars().next_back().filter(|ch| ch.is_whitespace()) {
        let prefix = &value[..value.len() - last.len_utf8()];
        if prefix
            .bytes()
            .rev()
            .take_while(|byte| *byte == b'\\')
            .count()
            % 2
            == 1
        {
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
        return escape_label(label.as_ref());
    }

    labels
        .iter()
        .map(|label| escape_label(label.as_ref()))
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
        .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')));

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

    match decode_preserved_labels(value) {
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
    let (labels, _) = decode_preserved_labels(name).map_err(failed)?;

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

        wire.push(u8::try_from(label.len()).map_err(|_| ParseNameError::LabelTooLong)?);
        wire.extend_from_slice(label);
    }

    wire.push(0);

    if wire.len() > MAX_WIRE_NAME_LEN {
        return Err(ParseNameError::TooLong);
    }

    Ok(wire)
}

/// Escape separators, backslashes, the origin marker `@`, and master-file
/// metacharacters (RFC 1035, Section 5.1).
const ESCAPED_IN_LABEL: &[u8] = b".\\@;()\"$";

/// Decode octet labels and enforce wire lengths; return whether the root was present.
/// An escaped final dot (`a\.`) is label data, not the root.
pub fn decode_name_labels(name: &str) -> Result<(Vec<Vec<u8>>, bool), ParseNameError> {
    let (mut labels, absolute) = decode_preserved_labels(name)?;
    for label in &mut labels {
        label.make_ascii_lowercase();
    }
    Ok((labels, absolute))
}

/// Decode octet labels without changing case, for RDATA storage and wire output.
pub(crate) fn decode_preserved_labels(name: &str) -> Result<(Vec<Vec<u8>>, bool), ParseNameError> {
    let mut labels = decode_labels(name)?;

    // The root's empty label terminates a name rather than being one. Deciding
    // that here keeps an escaped trailing dot (`a\.`) from reading as the root.
    let absolute = labels.len() > 1 && labels[labels.len() - 1].is_empty();

    if absolute {
        labels.pop();
    }

    for label in &labels {
        classify_owner_label(label)?;
    }

    classify_wire_len(&labels, &[])?;

    Ok((labels, absolute))
}

/// Decode a presentation-form name into octet labels, resolving the `\X`
/// and `\DDD` escapes (RFC 1035, Section 5.1).
fn decode_labels(name: &str) -> Result<Vec<Vec<u8>>, ParseNameError> {
    let mut labels = Vec::new();
    let mut label: Vec<u8> = Vec::new();
    let mut chars = name.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            ch if ch.is_ascii_whitespace() || ch.is_ascii_control() => {
                return Err(ParseNameError::Whitespace);
            }
            '.' => labels.push(mem::take(&mut label)),
            '\\' => match chars.peek() {
                Some(digit) if digit.is_ascii_digit() => {
                    let mut octet = 0u32;

                    for _ in 0..3 {
                        let digit = chars
                            .next()
                            .and_then(|ch| ch.to_digit(10))
                            .ok_or(ParseNameError::InvalidEscape)?;
                        octet = octet * 10 + digit;
                    }

                    label.push(u8::try_from(octet).map_err(|_| ParseNameError::InvalidEscape)?);
                }
                Some(&escaped) => {
                    chars.next();
                    let mut buffer = [0; 4];
                    label.extend_from_slice(escaped.encode_utf8(&mut buffer).as_bytes());
                }
                None => return Err(ParseNameError::DanglingEscape),
            },
            ch => {
                let mut buffer = [0; 4];
                label.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }

    labels.push(label);

    Ok(labels)
}

/// Validate only the DNS label length (RFC 2181, Section 11).
fn classify_owner_label(label: &[u8]) -> Result<(), ParseNameError> {
    if label.is_empty() {
        return Err(ParseNameError::EmptyLabel);
    }
    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ParseNameError::LabelTooLong);
    }

    Ok(())
}

/// Check the DNS wire-length limit in RFC 1035, Section 2.3.4, including each label's length
/// octet and the root terminator.
pub(crate) fn classify_wire_len(owner: &[Vec<u8>], zone: &[Vec<u8>]) -> Result<(), ParseNameError> {
    let wire_len = owner
        .iter()
        .chain(zone)
        .map(|label| label.len() + 1)
        .sum::<usize>()
        + 1;

    if wire_len > MAX_WIRE_NAME_LEN {
        return Err(ParseNameError::TooLong);
    }

    Ok(())
}

/// Escape a label without changing its octets; dots use decimal escapes so
/// a stored dot is always a label boundary (RFC 1035, Section 5.1).
fn escape_label(label: &[u8]) -> String {
    let mut escaped = String::with_capacity(label.len());

    for &byte in label {
        match byte {
            b'.' => escaped.push_str(r"\046"),
            0x21..=0x7e if !ESCAPED_IN_LABEL.contains(&byte) => escaped.push(char::from(byte)),
            byte if ESCAPED_IN_LABEL.contains(&byte) => {
                escaped.push('\\');
                escaped.push(char::from(byte));
            }
            byte => escaped.push_str(&format!("\\{byte:03}")),
        }
    }

    escaped
}

/// Return whether `suffix` is a label-wise suffix of `name` (the same name or under it).
pub fn is_label_suffix(name: &[Vec<u8>], suffix: &[Vec<u8>]) -> bool {
    name.len() >= suffix.len() && name[name.len() - suffix.len()..] == *suffix
}

/// Convert a typed name's wire bytes into the `domain` crate's form.
fn wire_to_name(wire: Vec<u8>) -> Result<WireName, EncodeWireNameError> {
    Name::from_octets(wire).map_err(|error| EncodeWireNameError::Octets(Box::new(error)))
}

#[cfg(test)]
mod tests;
