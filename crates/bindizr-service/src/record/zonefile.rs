use bindizr_core::dns::{name::to_fqdn_lowercase, txt::encode_raw_txt_rdata};
use domain::{
    base::iana::Class,
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
    pub value: ParsedValue,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}

/// The parsed value, ready to become a stored value. Non-TXT records carry a
/// `Request` that import re-encodes per type; TXT is pre-`Encoded` here so its
/// character-strings' raw octets — which may be non-UTF-8 (BIND `\DDD` escapes)
/// — survive instead of being mangled by a lossy UTF-8 conversion.
pub(super) enum ParsedValue {
    Request(RecordValueRequest),
    Encoded(String),
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

                let rtype = record.rtype().to_string();
                let record_type = match rtype.parse::<RecordType>() {
                    Ok(RecordType::SOA) => continue, // managed via zone fields
                    Ok(record_type) => record_type,
                    Err(_) => {
                        errors.push(format!(
                            "unsupported record type '{}' for '{}'",
                            rtype,
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
                        // Preserve raw character-string octets. TXT RDATA can hold
                        // arbitrary bytes (BIND writes them as `\DDD` escapes, which
                        // the scanner has already decoded); a UTF-8 conversion would
                        // replace non-UTF-8 bytes with U+FFFD and silently change the
                        // data served over DNS. Build the length-prefixed RDATA
                        // directly and store it byte-exact. Each character-string is
                        // <=255 bytes by the CharStr invariant.
                        let mut rdata = Vec::new();
                        for segment in txt.iter() {
                            rdata.push(segment.len() as u8);
                            rdata.extend_from_slice(segment);
                        }
                        (ParsedValue::Encoded(encode_raw_txt_rdata(&rdata)), None)
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
                                        (
                                            ParsedValue::Request(RecordValueRequest::String(rest)),
                                            Some(prio),
                                        )
                                    }
                                    None => (
                                        ParsedValue::Request(RecordValueRequest::String(raw)),
                                        None,
                                    ),
                                }
                            }
                            _ => (ParsedValue::Request(RecordValueRequest::String(raw)), None),
                        }
                    }
                };

                records.push(ParsedRecord {
                    owner_fqdn: record.owner().to_string().to_ascii_lowercase(),
                    record_type,
                    value,
                    ttl: Some(ttl),
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
    use bindizr_core::dns::txt::decode_raw_txt_rdata;

    use super::*;

    #[test]
    fn txt_preserves_non_utf8_octets() {
        // `\255\254` decode to bytes 0xFF 0xFE, which are not valid UTF-8. The
        // old `String::from_utf8_lossy` path turned them into U+FFFD; the stored
        // RDATA must instead hold the exact octets.
        let parsed = parse_zone_file("weird IN TXT \"\\255\\254\"\n", "example.com", 3600);
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
        let encoded = match &rec.value {
            ParsedValue::Encoded(s) => s,
            ParsedValue::Request(_) => panic!("TXT should be pre-encoded"),
        };
        let rdata = decode_raw_txt_rdata(encoded).expect("valid encoded TXT rdata");
        // One character-string of length 2 carrying the exact bytes.
        assert_eq!(rdata, vec![2u8, 0xFF, 0xFE]);
    }
}
