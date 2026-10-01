//! Reading BIND master-file text into records the record API can accept.

use domain::{
    base::iana::{Class, Rtype},
    rdata::ZoneRecordData,
    zonefile::inplace::{self, Entry, ScannedRecord, Zonefile},
};

use crate::{
    dns::{
        Serial, SoaInterval, Ttl,
        name::{ZoneName, to_fqdn_lowercase},
        record::NaptrRecordValue,
    },
    model::record::RecordType,
};

/// A record's value as the zone file spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneFileValue {
    /// Presentation-form rdata, for every type but TXT.
    Rdata(String),
    /// A TXT record's character-strings, already checked for UTF-8.
    Segments(Vec<String>),
}

/// One record from a BIND zone file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneFileRecord {
    /// Absolute owner name (e.g. `www.example.com.`).
    pub owner_fqdn: String,
    pub record_type: RecordType,
    pub value: ZoneFileValue,
    pub ttl: Ttl,
    pub priority: Option<i32>,
}

/// The zone fields a file's SOA carries, for creating a zone from it. The
/// record itself is never stored: a zone's SOA is built from its own columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneFileSoa {
    pub mname: String,
    pub rname: String,
    pub serial: Serial,
    pub refresh: SoaInterval,
    pub retry: SoaInterval,
    pub expire: SoaInterval,
    pub minimum_ttl: Ttl,
}

/// What a zone file yielded: its usable records, and what it could not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedZoneFile {
    pub records: Vec<ZoneFileRecord>,
    /// The apex SOA's fields, when the file carried one.
    pub soa: Option<ZoneFileSoa>,
    /// Human-readable problems (parse failure, out-of-range TTL, unsupported
    /// directive).
    pub errors: Vec<String>,
    /// Records bindizr has no type or class for, apart from `errors` so an
    /// import can pass over them.
    pub unsupported: Vec<String>,
}

impl ParsedZoneFile {
    /// Parse a BIND zone file using its origin and `default_ttl` for omitted TTLs.
    /// Keep the SOA separately: the zone stores its fields, not an SOA record.
    pub fn parse(content: &str, zone_name: &ZoneName, default_ttl: Ttl) -> Self {
        let origin_fqdn = zone_name.to_fqdn();

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

        let mut records = Vec::new();
        let mut errors = Vec::new();
        let mut unsupported = Vec::new();
        let mut soa = None;

        loop {
            match zonefile.next_entry() {
                Ok(Some(Entry::Record(record))) => {
                    if record.class() != Class::IN {
                        unsupported.push(format!(
                            "unsupported record class '{}' for '{}'",
                            record.class(),
                            record.owner()
                        ));
                        continue;
                    }

                    let record_type = match record.rtype() {
                        // Only the apex SOA supplies this zone's serial and timers.
                        Rtype::SOA => {
                            if to_fqdn_lowercase(&record.owner().to_string()) != origin_fqdn {
                                errors.push(format!(
                                    "SOA for '{}' does not belong to zone '{}'",
                                    record.owner(),
                                    origin_fqdn
                                ));
                            } else if soa.is_some() {
                                errors.push(format!(
                                    "zone '{}' carries more than one SOA",
                                    origin_fqdn
                                ));
                            } else {
                                soa = to_zone_file_soa(&record);
                            }
                            continue;
                        }
                        other => match RecordType::try_from(other) {
                            Ok(record_type) => record_type,
                            Err(_) => {
                                unsupported.push(format!(
                                    "unsupported record type '{}' for '{}'",
                                    other,
                                    record.owner()
                                ));
                                continue;
                            }
                        },
                    };

                    // Reject TTLs past the stored range (like the JSON and
                    // nsupdate paths) instead of silently corrupting them.
                    let ttl_secs = record.ttl().as_secs();
                    let Ok(ttl) = Ttl::try_from(ttl_secs) else {
                        errors.push(format!(
                            "TTL {} for '{}' exceeds the maximum of {}",
                            ttl_secs,
                            record.owner(),
                            i32::MAX
                        ));
                        continue;
                    };

                    let (value, priority) = match record.data() {
                        // Rendered from the parsed fields: `domain` appends the
                        // absolute dot to a name it already renders as `.`, so its
                        // form spells a root replacement `..`.
                        ZoneRecordData::Naptr(naptr) => match NaptrRecordValue::from_wire(
                            naptr.order(),
                            naptr.preference(),
                            naptr.flags().as_slice(),
                            naptr.services().as_slice(),
                            naptr.regexp().as_slice(),
                            &naptr.replacement().to_string(),
                        )
                        .map(|value| value.canonical())
                        {
                            Ok(text) => (ZoneFileValue::Rdata(text), None),
                            Err(e) => {
                                errors.push(format!("NAPTR value for '{}': {}", record.owner(), e));
                                continue;
                            }
                        },
                        ZoneRecordData::Txt(txt) => {
                            // TXT values must be valid UTF-8; reject non-UTF-8
                            // octets (e.g. BIND `\DDD` escapes) rather than
                            // storing them.
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
                            (ZoneFileValue::Segments(segments), None)
                        }
                        other => {
                            let raw = other.to_string();
                            // Move the MX/SRV priority (first field) into the
                            // priority column like the JSON API; both forms
                            // canonicalize equal.
                            match record_type {
                                RecordType::Mx | RecordType::Srv => {
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

                    records.push(ZoneFileRecord {
                        owner_fqdn: to_fqdn_lowercase(&record.owner().to_string()),
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

        ParsedZoneFile {
            records,
            soa,
            errors,
            unsupported,
        }
    }
}

/// Read an SOA record's fields, or `None` when a timer does not fit the i32
/// columns a zone stores them in.
fn to_zone_file_soa(record: &ScannedRecord) -> Option<ZoneFileSoa> {
    let ZoneRecordData::Soa(soa) = record.data() else {
        return None;
    };
    let interval = |value: domain::base::Ttl| SoaInterval::try_from(value.as_secs()).ok();
    Some(ZoneFileSoa {
        mname: soa.mname().to_string(),
        // The mailbox is rendered in its SOA form (`admin.example.com.`); the
        // service turns it back into an address.
        rname: soa.rname().to_string(),
        serial: Serial::from(soa.serial().into_int()),
        refresh: interval(soa.refresh())?,
        retry: interval(soa.retry())?,
        expire: interval(soa.expire())?,
        minimum_ttl: Ttl::try_from(soa.minimum().as_secs()).ok()?,
    })
}

/// Directives `ParsedZoneFile::parse` prepends before handing the text to the parser.
const PRELUDE_LINES: usize = 2;

/// Restate a parser error in the submitted text's line numbering. `Error` keeps
/// its position private, so its `{line}:{col}: {reason}` rendering is all there is.
fn to_input_line_message(err: &inplace::Error) -> String {
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
mod tests;
