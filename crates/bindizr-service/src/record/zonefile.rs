use bindizr_core::dns::name::to_fqdn_lowercase;
use domain::{
    base::iana::{Class, Rtype},
    rdata::ZoneRecordData,
    zonefile::inplace::{Entry, Zonefile},
};

use crate::{model::record::RecordType, types::RecordValueRequest};

/// A single record extracted from a BIND zone file, expressed in the same
/// input shape the record API accepts.
pub(super) struct ParsedRecord {
    /// Absolute owner name (e.g. `www.example.com.`).
    pub owner_fqdn: String,
    pub record_type: RecordType,
    pub value: RecordValueRequest,
    pub ttl: i32,
    pub priority: Option<i32>,
}

pub(super) struct ParsedZoneFile {
    pub records: Vec<ParsedRecord>,
    /// Human-readable problems (unsupported type, non-IN class, parse failure).
    pub errors: Vec<String>,
}

/// Parse BIND zone file text relative to `zone_name`. Relative names resolve
/// against the origin, missing TTLs fall back to `default_ttl`, and SOA records
/// are ignored (the zone's SOA comes from its own fields).
pub(super) fn parse_zone_file(content: &str, zone_name: &str, default_ttl: i32) -> ParsedZoneFile {
    let origin_fqdn = to_fqdn_lowercase(zone_name);

    // Feed $ORIGIN/$TTL as directives so the parser resolves relative names and TTLs.
    let mut buffer = format!("$ORIGIN {origin_fqdn}\n$TTL {default_ttl}\n");
    buffer.push_str(content);
    if !buffer.ends_with('\n') {
        buffer.push('\n');
    }

    let mut zonefile = Zonefile::new();
    zonefile.set_default_class(Class::IN);
    zonefile.extend_from_slice(buffer.as_bytes());

    let mut records = Vec::new();
    let mut errors = Vec::new();

    loop {
        match zonefile.next_entry() {
            Ok(Some(Entry::Record(record))) => {
                if record.class() != Class::IN {
                    errors.push(format!(
                        "unsupported record class '{}' for '{}'",
                        record.class(),
                        record.owner()
                    ));
                    continue;
                }

                let record_type = match record.rtype() {
                    Rtype::SOA => continue, // managed via zone fields
                    Rtype::A => RecordType::A,
                    Rtype::AAAA => RecordType::AAAA,
                    Rtype::CNAME => RecordType::CNAME,
                    Rtype::MX => RecordType::MX,
                    Rtype::TXT => RecordType::TXT,
                    Rtype::NS => RecordType::NS,
                    Rtype::SRV => RecordType::SRV,
                    Rtype::PTR => RecordType::PTR,
                    other => {
                        errors.push(format!(
                            "unsupported record type '{}' for '{}'",
                            other,
                            record.owner()
                        ));
                        continue;
                    }
                };

                // Stored as i32; reject TTLs that would wrap negative (like the
                // JSON and nsupdate paths) instead of silently corrupting them.
                let ttl_secs = record.ttl().as_secs();
                if ttl_secs > i32::MAX as u32 {
                    errors.push(format!(
                        "TTL {} for '{}' exceeds the maximum of {}",
                        ttl_secs,
                        record.owner(),
                        i32::MAX
                    ));
                    continue;
                }
                let ttl = ttl_secs as i32;

                let (value, priority) = match record.data() {
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
                            errors.push(format!(
                                "TXT value for '{}' is not valid UTF-8",
                                record.owner()
                            ));
                            continue;
                        }
                        (RecordValueRequest::Segments(segments), None)
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
                                        (RecordValueRequest::String(rest), Some(prio))
                                    }
                                    None => (RecordValueRequest::String(raw), None),
                                }
                            }
                            _ => (RecordValueRequest::String(raw), None),
                        }
                    }
                };

                records.push(ParsedRecord {
                    owner_fqdn: record.owner().to_string().to_ascii_lowercase(),
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
                errors.push(format!("failed to parse zone file: {e}"));
                break;
            }
        }
    }

    ParsedZoneFile { records, errors }
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
                .records
                .iter()
                .any(|r| r.record_type == RecordType::TXT),
            "the non-UTF-8 TXT record should not have been stored"
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
        let rec = parsed
            .records
            .iter()
            .find(|r| r.record_type == RecordType::TXT)
            .expect("a TXT record");
        match &rec.value {
            RecordValueRequest::Segments(segments) => assert_eq!(segments, &["foo", "bar"]),
            other => panic!("expected segments, got {other:?}"),
        }
    }
}
