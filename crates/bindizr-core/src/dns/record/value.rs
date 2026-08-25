//! Shared field parsing/validation helpers for stored record values.

use crate::dns::{
    DNS_TCP_MAX_SIZE,
    name::{MAX_DOMAIN_LEN, has_whitespace_or_control, validate_domain_label},
};

/// Priority an MX or SRV row takes when its priority column is NULL; served
/// and compared as this value, so both types must agree on it.
pub(crate) const DEFAULT_PRIORITY: u16 = 10;

/// Maximum RDATA bytes for one stored record: the TCP message limit less the
/// header and worst-case question and answer fields (wire names take
/// `MAX_DOMAIN_LEN` + 2), so any accepted record fits a single-answer
/// transfer message.
pub(crate) const MAX_RECORD_RDATA: usize =
    DNS_TCP_MAX_SIZE - 12 - (MAX_DOMAIN_LEN + 2 + 4) - (MAX_DOMAIN_LEN + 2 + 10);

pub(crate) fn parse_optional_u16_record_field(
    field: &str,
    value: Option<i32>,
    default: u16,
) -> Result<u16, String> {
    value.map_or(Ok(default), |value| {
        u16::try_from(value).map_err(|_| format!("{field} must be between 0 and 65535"))
    })
}

pub(crate) fn parse_u8_record_field(field: &str, value: &str) -> Result<u8, String> {
    value
        .parse::<u8>()
        .map_err(|_| format!("{field} must be an unsigned 8-bit integer: {value}"))
}

/// Decode a hex field that presentation form may split into whitespace-
/// separated groups, as `dig` prints. RFC 1035 `(`/`)` markers are dropped:
/// nsupdate and import re-parse `domain`'s form, which wraps hex in them.
pub(crate) fn parse_hex_record_field<'a>(
    field: &str,
    groups: impl Iterator<Item = &'a str>,
) -> Result<Vec<u8>, String> {
    let hex: String = groups
        .filter(|group| !matches!(*group, "(" | ")"))
        .collect();
    let hex = hex.as_str();
    if hex.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if hex.len() % 2 != 0 {
        return Err(format!("{field} must be an even number of hex digits"));
    }
    // Decoded from bytes, not `&str` slices: a multi-byte character must fail
    // as non-hex instead of panicking on a char boundary.
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16);
            let lo = (pair[1] as char).to_digit(16);
            hi.zip(lo)
                .map(|(hi, lo)| (hi * 16 + lo) as u8)
                .ok_or_else(|| format!("{field} must be hex"))
        })
        .collect()
}

pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

pub(crate) fn parse_u16_record_field(field: &str, value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("{field} must be an unsigned 16-bit integer: {value}"))
}

pub(crate) fn validate_domain_record_value(field: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(format!("{} must not be empty", field));
    }

    if has_whitespace_or_control(value) {
        return Err(format!(
            "{} must not contain whitespace or control characters",
            field
        ));
    }

    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing_dot.is_empty() {
        return Err(format!("{} must not be the root zone", field));
    }

    if without_trailing_dot.len() > MAX_DOMAIN_LEN {
        return Err(format!("{} must be 253 bytes or fewer", field));
    }

    for label in without_trailing_dot.split('.') {
        validate_domain_label(label, field, true)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_domain_record_value;

    // RFC 1035, Section 5.1 lets presentation form quote any character; bindizr
    // refuses it so that no label can hide a `.` that reads as a boundary.
    #[test]
    fn rejects_escaped_name_values() {
        for value in [
            r"host\-name.example.com.", // decodes to a valid name, still refused
            r"evil\.example.com",       // the impersonation the rule exists for
            r"a\\b.example.com",
            r"host\065.example.com",
        ] {
            assert!(
                validate_domain_record_value("CNAME record value", value).is_err(),
                "{value} was accepted"
            );
        }
    }

    #[test]
    fn accepts_plain_names_with_or_without_a_trailing_dot() {
        for value in [
            "host-name.example.com.",
            "host-name.example.com",
            "_dmarc.example.com.",
        ] {
            validate_domain_record_value("CNAME record value", value).unwrap();
        }
    }
}
