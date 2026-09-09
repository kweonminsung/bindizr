//! Reading BIND master-file text into records the record API can accept.

use domain::{
    base::iana::{Class, Rtype},
    rdata::ZoneRecordData,
    zonefile::inplace::{Entry, Error as ZoneFileError, Zonefile},
};

use crate::{dns::name::to_fqdn_lowercase, model::record::RecordType};

/// An RR's value as the zone file spells it.
#[derive(Debug, PartialEq, Eq)]
pub enum ZoneFileValue {
    /// Presentation-form rdata, for every type but TXT.
    Rdata(String),
    /// A TXT record's character-strings, already checked for UTF-8.
    CharacterStrings(Vec<String>),
}

/// One RR from a BIND zone file.
pub struct ZoneFileRr {
    /// Absolute owner name (e.g. `www.example.com.`).
    pub owner_fqdn: String,
    pub record_type: RecordType,
    pub value: ZoneFileValue,
    pub ttl: i32,
    pub priority: Option<i32>,
}

pub struct ParsedZoneFile {
    pub rrs: Vec<ZoneFileRr>,
    /// Human-readable problems (unsupported type, non-IN class, parse failure).
    pub errors: Vec<String>,
}

/// Parse BIND zone file text relative to `zone_name`. Relative names resolve
/// against the origin, missing TTLs fall back to `default_ttl`, and SOA records
/// are ignored (the zone's SOA comes from its own fields).
pub fn parse_zone_file(content: &str, zone_name: &str, default_ttl: i32) -> ParsedZoneFile {
    let origin_fqdn = to_fqdn_lowercase(zone_name);

    // Feed $ORIGIN/$TTL as directives so the parser resolves relative names and
    // TTLs. PRELUDE_LINES counts them.
    let mut buffer = format!("$ORIGIN {origin_fqdn}\n$TTL {default_ttl}\n");
    buffer.push_str(content);
    if !buffer.ends_with('\n') {
        buffer.push('\n');
    }

    let mut zonefile = Zonefile::new();
    zonefile.set_default_class(Class::IN);
    zonefile.extend_from_slice(buffer.as_bytes());

    let mut rrs = Vec::new();
    let mut errors = Vec::new();

    loop {
        match zonefile.next_entry() {
            Ok(Some(Entry::Record(rr))) => {
                if rr.class() != Class::IN {
                    errors.push(format!(
                        "unsupported record class '{}' for '{}'",
                        rr.class(),
                        rr.owner()
                    ));
                    continue;
                }

                let record_type = match rr.rtype() {
                    Rtype::SOA => continue, // managed via zone fields
                    other => match RecordType::from_rtype(other) {
                        Ok(record_type) => record_type,
                        Err(_) => {
                            errors.push(format!(
                                "unsupported record type '{}' for '{}'",
                                other,
                                rr.owner()
                            ));
                            continue;
                        }
                    },
                };

                // Stored as i32; reject TTLs that would wrap negative (like the
                // JSON and nsupdate paths) instead of silently corrupting them.
                let ttl_secs = rr.ttl().as_secs();
                if ttl_secs > i32::MAX as u32 {
                    errors.push(format!(
                        "TTL {} for '{}' exceeds the maximum of {}",
                        ttl_secs,
                        rr.owner(),
                        i32::MAX
                    ));
                    continue;
                }
                let ttl = ttl_secs as i32;

                let (value, priority) = match rr.data() {
                    ZoneRecordData::Txt(txt) => {
                        // TXT values must be valid UTF-8; reject non-UTF-8 octets
                        // (e.g. BIND `\DDD` escapes) rather than storing them.
                        let mut segments = Vec::new();
                        let mut non_utf8 = false;
                        for segment in txt.iter() {
                            match std::str::from_utf8(segment) {
                                Ok(text) => segments.push(text.to_string()),
                                Err(_) => {
                                    non_utf8 = true;
                                    break;
                                }
                            }
                        }
                        if non_utf8 {
                            errors
                                .push(format!("TXT value for '{}' is not valid UTF-8", rr.owner()));
                            continue;
                        }
                        (ZoneFileValue::CharacterStrings(segments), None)
                    }
                    other => {
                        let raw = other.to_string();
                        // Move the MX/SRV priority (first field) into the priority
                        // column like the JSON API; both forms canonicalize equal.
                        match record_type {
                            RecordType::MX | RecordType::SRV => {
                                let mut fields = raw.split_whitespace();
                                match fields.next().and_then(|p| p.parse::<i32>().ok()) {
                                    Some(prio) => {
                                        let rest = fields.collect::<Vec<_>>().join(" ");
                                        (ZoneFileValue::Rdata(rest), Some(prio))
                                    }
                                    None => (ZoneFileValue::Rdata(raw), None),
                                }
                            }
                            _ => (ZoneFileValue::Rdata(raw), None),
                        }
                    }
                };

                rrs.push(ZoneFileRr {
                    owner_fqdn: to_fqdn_lowercase(&rr.owner().to_string()),
                    record_type,
                    value,
                    ttl,
                    priority,
                });
            }
            Ok(Some(Entry::Include { .. })) => {
                errors.push("$INCLUDE directives are not supported".to_string());
            }
            Ok(None) => break,
            Err(e) => {
                errors.push(format!(
                    "failed to parse zone file: {}",
                    to_input_line_message(&e)
                ));
                // domain documents the scanner as invalid once an entry fails.
                break;
            }
        }
    }

    ParsedZoneFile { rrs, errors }
}

/// Directives `parse_zone_file` prepends before handing the text to the parser.
const PRELUDE_LINES: usize = 2;

/// Restate a parser error in the submitted text's line numbering. `Error` keeps
/// its position private, so its `{line}:{col}: {reason}` rendering is all there is.
fn to_input_line_message(err: &ZoneFileError) -> String {
    let message = err.to_string();
    match message.split_once(':') {
        Some((line, rest)) => match line.parse::<usize>() {
            Ok(line) if line > PRELUDE_LINES => format!("{}:{}", line - PRELUDE_LINES, rest),
            _ => message,
        },
        None => message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_rejects_non_utf8_octets() {
        // `\255\254` decode to bytes 0xFF 0xFE, which are not valid UTF-8.
        let parsed = parse_zone_file("weird IN TXT \"\\255\\254\"\n", "example.com", 3600);
        assert!(
            parsed.errors.iter().any(|e| e.contains("not valid UTF-8")),
            "expected a UTF-8 error, got: {:?}",
            parsed.errors
        );
        assert!(
            !parsed
                .rrs
                .iter()
                .any(|rr| rr.record_type == RecordType::TXT),
            "the non-UTF-8 TXT record should not have been stored"
        );
    }

    #[test]
    fn parse_error_names_the_line_of_the_submitted_text() {
        // An unknown rtype is caught where it sits; an rdata error is reported
        // at the end of the entry, which would blur what this pins down.
        let parsed = parse_zone_file(
            "ok IN A 192.0.2.1\nbad !!! IN A 192.0.2.2\n",
            "example.com",
            3600,
        );
        assert!(
            parsed.errors.iter().any(|e| e.contains(": 2:")),
            "expected the error to name line 2, got: {:?}",
            parsed.errors
        );
    }

    #[test]
    fn txt_utf8_multi_segment_parses_as_segments() {
        let parsed = parse_zone_file("multi IN TXT \"foo\" \"bar\"\n", "example.com", 3600);
        assert!(
            parsed.errors.is_empty(),
            "unexpected errors: {:?}",
            parsed.errors
        );
        let rr = parsed
            .rrs
            .iter()
            .find(|rr| rr.record_type == RecordType::TXT)
            .expect("a TXT record");
        match &rr.value {
            ZoneFileValue::CharacterStrings(segments) => assert_eq!(segments, &["foo", "bar"]),
            other => panic!("expected segments, got {other:?}"),
        }
    }
}
