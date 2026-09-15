//! Shared field parsing/validation helpers for stored record values.

use super::txt::TxtRecordValue;
use crate::dns::{
    DNS_TCP_MAX_SIZE,
    name::{MAX_DOMAIN_LEN, decode_name_labels, has_whitespace_or_control},
    tsig::MAX_TSIG_RR,
};

/// Priority an MX or SRV row takes when its priority column is NULL; served
/// and compared as this value, so both types must agree on it.
pub(crate) const DEFAULT_PRIORITY: u16 = 10;

/// Maximum RDATA bytes for one stored record: the TCP message limit less the
/// header, worst-case question and answer fields, and the TSIG a signed
/// transfer appends. A record cannot be split across messages, so an accepted
/// one must fit an envelope whether or not the secondary asked with a key.
pub(crate) const MAX_RECORD_RDATA: usize =
    DNS_TCP_MAX_SIZE - 12 - (MAX_DOMAIN_LEN + 2 + 4) - (MAX_DOMAIN_LEN + 2 + 10) - MAX_TSIG_RR;

/// Parse an optional unsigned 16-bit record field.
pub(crate) fn parse_optional_u16_record_field(
    field: &str,
    value: Option<i32>,
    default: u16,
) -> Result<u16, String> {
    value.map_or(Ok(default), |value| {
        u16::try_from(value).map_err(|_| format!("{field} must be between 0 and 65535"))
    })
}

/// Parse an unsigned 8-bit record field.
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
    if !hex.len().is_multiple_of(2) {
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

/// Encode bytes as uppercase hexadecimal text.
pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// Parse an unsigned 16-bit record field.
pub(crate) fn parse_u16_record_field(field: &str, value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("{field} must be an unsigned 16-bit integer: {value}"))
}

/// One leading quoted string and what follows it, for the rdata grammars that
/// mix them with other fields. `\\` escapes a byte and `\\DDD` a decimal one, as
/// RFC 1035, Section 5.1 spells them. The caller bounds its own field.
pub(crate) fn parse_quoted_string<'a>(
    field: &str,
    input: &'a str,
) -> Result<(String, &'a str), String> {
    let rest = input
        .strip_prefix('"')
        .ok_or_else(|| format!("{field} must be a quoted string: {input}"))?;

    let mut out = Vec::new();
    let mut bytes = rest.bytes().enumerate();
    while let Some((index, byte)) = bytes.next() {
        match byte {
            b'"' => {
                let consumed = &rest[index + 1..];
                let text =
                    String::from_utf8(out).map_err(|_| format!("{field} must be valid UTF-8"))?;
                return Ok((text, consumed.trim_start()));
            }
            b'\\' => match bytes.next() {
                Some((_, d @ b'0'..=b'9')) => {
                    let d2 = bytes.next().map(|(_, b)| b).filter(u8::is_ascii_digit);
                    let d3 = bytes.next().map(|(_, b)| b).filter(u8::is_ascii_digit);
                    let (Some(d2), Some(d3)) = (d2, d3) else {
                        return Err(format!("{field} contains an invalid \\DDD escape"));
                    };
                    let code = u16::from(d - b'0') * 100
                        + u16::from(d2 - b'0') * 10
                        + u16::from(d3 - b'0');
                    let byte = u8::try_from(code)
                        .map_err(|_| format!("{field} contains an invalid \\DDD escape"))?;
                    out.push(byte);
                }
                Some((_, escaped)) => out.push(escaped),
                None => return Err(format!("{field} ends in a dangling escape")),
            },
            other => out.push(other),
        }
    }

    Err(format!("{field} has an unterminated quote"))
}

/// A character-string: [`parse_quoted_string`] under the 255-byte limit
/// RFC 1035, Section 3.3 puts on one.
pub(crate) fn parse_char_string<'a>(
    field: &str,
    input: &'a str,
) -> Result<(String, &'a str), String> {
    let (text, rest) = parse_quoted_string(field, input)?;
    if text.len() > 255 {
        return Err(format!("{field} must be 255 bytes or less"));
    }

    Ok((text, rest))
}

/// A string in the quoted form the rdata grammars store: the TXT rendering,
/// so a control or non-ASCII byte is a `\DDD` escape a text column can hold.
pub(crate) fn to_quoted_string(text: &str) -> String {
    TxtRecordValue::to_quoted_charstr(text.as_bytes())
}

/// Validate a domain-name record value with the same decoded-label rules as an owner name.
///
/// Splitting on `.` would break escaped dots; non-LDH labels also occur in RFC 2317, Section 4
/// delegations such as `0/25`.
pub(crate) fn validate_domain_record_value(field: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(format!("{} must not be empty", field));
    }

    // Escapes reach the labels below; this catches the raw octets, which no
    // presentation form can spell back.
    if has_whitespace_or_control(value) {
        return Err(format!(
            "{} must not contain whitespace or control characters",
            field
        ));
    }

    if trimmed == "." {
        return Err(format!("{} must not be the root zone", field));
    }

    decode_name_labels(trimmed).map_err(|e| format!("{} {}", field, e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{to_quoted_string, validate_domain_record_value};

    /// Verify that `to_quoted_string` escapes control and non-ASCII bytes.
    #[test]
    fn to_quoted_string_escapes_control_and_non_ascii_bytes() {
        // RFC 1035, Section 5.1 spells such octets `\DDD`, and a raw NUL is
        // what a PostgreSQL text column refuses.
        assert_eq!(to_quoted_string("a\u{0}b"), r#""a\000b""#);
        assert_eq!(to_quoted_string("caf\u{e9}"), r#""caf\195\169""#);
        assert_eq!(to_quoted_string(r#"say "hi"\"#), r#""say \"hi\"\\""#);
    }

    /// Verify that domain-name record values accept the same labels as owner names.
    ///
    /// RFC 2181, Section 11 permits non-LDH labels; both canonicalization and wire encoding
    /// decode them before use.
    #[test]
    fn accepts_the_labels_an_owner_name_may_carry() {
        for value in [
            r"evil\.example.com", // one label `evil.example`, not a subdomain
            r"a\\b.example.com",
            r"host\065.example.com",
            "1.0/25.2.0.192.in-addr.arpa.", // RFC 2317, Section 4 delegation
            "_dmarc.example.com.",
            "host-name.example.com",
        ] {
            validate_domain_record_value("CNAME record value", value)
                .unwrap_or_else(|e| panic!("{value} was rejected: {e}"));
        }
    }

    /// Verify rejection of record names that cannot round-trip through presentation text.
    #[test]
    fn rejects_what_no_presentation_form_spells_back() {
        for value in [
            "",
            ".",
            "bad target.example.com",
            " leading.example.com",
            "trailing.example.com ",
            "bad..example.com",
            r"dangling\",
            r"short\09.example.com",
        ] {
            assert!(
                validate_domain_record_value("CNAME record value", value).is_err(),
                "{value} was accepted"
            );
        }
    }
}
