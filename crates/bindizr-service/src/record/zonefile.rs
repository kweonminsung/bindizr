use bindizr_core::dns::name::to_fqdn_lowercase;
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
    pub value: RecordValueRequest,
    pub ttl: Option<i32>,
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

                let value = match record.data() {
                    ZoneRecordData::Txt(txt) => RecordValueRequest::Segments(
                        txt.iter()
                            .map(|segment| String::from_utf8_lossy(segment).into_owned())
                            .collect(),
                    ),
                    other => RecordValueRequest::String(other.to_string()),
                };

                records.push(ParsedRecord {
                    owner_fqdn: record.owner().to_string().to_ascii_lowercase(),
                    record_type,
                    value,
                    ttl: Some(record.ttl().as_secs() as i32),
                    priority: None,
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
