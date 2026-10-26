//! Match Accept headers against the webhook response media type.

use axum::http::HeaderMap;
use axum::http::header::ACCEPT;

/// Maximum fractional precision of an HTTP qvalue (RFC 9110, Section 12.4.2).
const QUALITY_PRECISION: usize = 3;

/// Unit quality expressed at the parser's fixed decimal precision.
const QUALITY_SCALE: u16 = 10u16.pow(QUALITY_PRECISION as u32);

/// Check whether Accept permits the response (RFC 9110, Section 12.5.1).
/// The most specific range determines quality; an absent header accepts any type.
pub(crate) fn is_acceptable(headers: &HeaderMap) -> bool {
    if !headers.contains_key(ACCEPT) {
        return true;
    }

    let mut preferred = None;

    for header in headers.get_all(ACCEPT) {
        let Ok(value) = header.to_str() else {
            return false;
        };

        for range in split_quoted(value, ',') {
            let Some((specificity, quality)) = match_range(range) else {
                continue;
            };

            if preferred
                .is_none_or(|(rank, q)| specificity > rank || (specificity == rank && quality > q))
            {
                preferred = Some((specificity, quality));
            }
        }
    }

    preferred.is_some_and(|(_, quality)| quality > 0)
}

/// Read a matching range's specificity and quality in thousandths.
fn match_range(range: &str) -> Option<((u8, bool), u16)> {
    let mut parts = split_quoted(range, ';');
    let (media_type, subtype) = parts.next()?.trim().split_once('/')?;
    let specificity = if media_type == "*" && subtype == "*" {
        0
    } else if media_type.eq_ignore_ascii_case("application") && subtype == "*" {
        1
    } else if media_type.eq_ignore_ascii_case("application")
        && subtype.eq_ignore_ascii_case("external.dns.webhook+json")
    {
        2
    } else {
        return None;
    };
    let mut version = false;
    let mut quality = None;

    for parameter in parts {
        // Empty parameters are permitted by RFC 9110, Section 5.6.6.
        let parameter = parameter.trim_matches([' ', '\t']);

        if parameter.is_empty() {
            continue;
        }

        let (name, value) = parameter.split_once('=')?;

        if name.eq_ignore_ascii_case("version") && !version {
            if parameter_value(value)? != "1" {
                return None;
            }
            version = true;
        } else if name.eq_ignore_ascii_case("q") && quality.is_none() {
            quality = Some(parse_quality(value)?);
        } else {
            // The representation has no other parameters; duplicates are malformed.
            return None;
        }
    }

    Some(((specificity, version), quality.unwrap_or(QUALITY_SCALE)))
}

/// Split a list while preserving quoted delimiters and escaped quotes.
fn split_quoted(value: &str, delimiter: char) -> impl Iterator<Item = &str> {
    let mut quoted = false;
    let mut escaped = false;

    value.split(move |ch| {
        if escaped {
            escaped = false;
        } else if quoted && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if !quoted && ch == delimiter {
            return true;
        }

        false
    })
}

/// Decode a token or quoted-string parameter (RFC 9110, Sections 5.6.2 and 5.6.4).
fn parameter_value(value: &str) -> Option<String> {
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        let mut decoded = String::new();
        let mut escaped = false;

        for ch in inner.chars() {
            if ch != '\t' && (ch < ' ' || ch == '\u{7f}') {
                return None;
            }

            if escaped {
                decoded.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                return None;
            } else {
                decoded.push(ch);
            }
        }

        return (!escaped).then_some(decoded);
    }

    (!value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)))
    .then(|| value.to_string())
}

/// Parse an HTTP qvalue without rounding (RFC 9110, Section 12.4.2).
fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));

    if fraction.len() > QUALITY_PRECISION || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    match whole {
        "0" => Some(
            fraction
                .bytes()
                .fold(0, |q, byte| q * 10 + u16::from(byte - b'0'))
                * 10u16.pow((QUALITY_PRECISION - fraction.len()) as u32),
        ),
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(QUALITY_SCALE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// Check equivalent ranges, multiple fields, and quality precedence.
    #[test]
    fn accept_matches_media_ranges_and_quality_precedence() {
        let mut headers = HeaderMap::new();

        assert!(is_acceptable(&headers));

        for (accept, supported) in [
            ("APPLICATION/EXTERNAL.DNS.WEBHOOK+JSON;VERSION=1", true),
            ("application/external.dns.webhook+json; version=\"1\"", true),
            (
                r#"application/external.dns.webhook+json;version="\1""#,
                true,
            ),
            ("application/*;q=0.5", true),
            ("*/*", true),
            ("text/plain, application/external.dns.webhook+json", true),
            ("application/external.dns.webhook+json;version=10", false),
            (
                "application/external.dns.webhook+json;version=1;q=0, */*;q=1",
                false,
            ),
            ("application/*;q=0, */*;q=1", false),
            (
                "application/external.dns.webhook+json;version=1;q=0.2, application/external.dns.webhook+json;q=0",
                true,
            ),
            (r#"text/plain;note="a,b;c", application/*"#, true),
            (
                "application/external.dns.webhook+json;version=1;q=1.001",
                false,
            ),
            (
                "application/external.dns.webhook+json;version=1;q=0.0001",
                false,
            ),
            (
                "application/external.dns.webhook+json;version=1;q=\"1\"",
                false,
            ),
            (
                "application/external.dns.webhook+json;version=1;version=1",
                false,
            ),
            (
                "application/external.dns.webhook+json;version=1;unknown=x",
                false,
            ),
            ("application/external.dns.webhook+json;version=\"1", false),
            ("", false),
        ] {
            headers.insert(ACCEPT, HeaderValue::from_str(accept).unwrap());
            assert_eq!(is_acceptable(&headers), supported, "{accept}");
        }

        headers.insert(ACCEPT, HeaderValue::from_static("*/*;q=1"));
        headers.append(ACCEPT, HeaderValue::from_static("application/*;q=0"));

        assert!(!is_acceptable(&headers));
        headers.append(
            ACCEPT,
            HeaderValue::from_static("application/external.dns.webhook+json;version=1;q=0.1"),
        );

        assert!(is_acceptable(&headers));
    }
}
