//! Convert BIND master files and AXFR records into import data.

mod wks;

use domain::{
    base::{
        ToName,
        iana::{Class, Rtype},
        name::ParsedName,
        rdata::{ComposeRecordData, ParseRecordData},
    },
    dep::octseq::parse::Parser,
    rdata::ZoneRecordData,
    zonefile::inplace::{self, Entry, Zonefile},
};

use crate::{
    dns::{
        Serial, SoaInterval, Ttl,
        name::{ZoneName, to_fqdn_lowercase},
        query::TransferRecord,
        record::{NaptrRecordValue, WksRecordValue},
    },
    model::record::RecordType,
};

/// A record's value as the zone file spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneFileValue {
    /// Presentation-form RDATA, including TXT with non-UTF-8 octets.
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
}

impl ParsedZoneFile {
    /// Parse a BIND zone file using its origin and `default_ttl` for omitted TTLs.
    /// Keep the SOA separately: the zone stores its fields, not an SOA record.
    pub fn parse(content: &str, zone_name: &ZoneName, default_ttl: Ttl) -> Self {
        let content = match wks::normalize_records(content) {
            Ok(content) => content,
            Err(error) => {
                return Self {
                    records: Vec::new(),
                    soa: None,
                    errors: vec![error],
                };
            }
        };
        let origin_fqdn = zone_name.to_fqdn();

        // Feed $ORIGIN/$TTL as directives so the parser resolves relative names and
        // TTLs. PRELUDE_LINES counts them.
        let mut buffer = format!("$ORIGIN {origin_fqdn}\n$TTL {default_ttl}\n");
        buffer.push_str(&content);
        if !buffer.ends_with('\n') {
            buffer.push('\n');
        }

        let mut zonefile = Zonefile::new();
        zonefile.set_default_class(Class::IN);
        zonefile.extend_from_slice(buffer.as_bytes());

        let mut parsed = Self {
            records: Vec::new(),
            soa: None,
            errors: Vec::new(),
        };

        loop {
            match zonefile.next_entry() {
                Ok(Some(Entry::Record(record))) => {
                    if record.class() != Class::IN {
                        parsed.errors.push(format!(
                            "unsupported record class '{}' for '{}'",
                            record.class(),
                            record.owner()
                        ));
                        continue;
                    }

                    parsed.push_record(
                        &origin_fqdn,
                        record.owner().to_string(),
                        record.rtype(),
                        record.ttl().as_secs(),
                        record.data(),
                    );
                }
                Ok(Some(Entry::Include { .. })) => {
                    parsed
                        .errors
                        .push("$INCLUDE directives are not supported".to_string());
                }
                Ok(None) => break,
                Err(e) => {
                    parsed.errors.push(format!(
                        "failed to parse zone file: {}",
                        to_input_line_message(&e)
                    ));
                    // domain documents the scanner as invalid once an entry fails.
                    break;
                }
            }
        }

        parsed
    }

    /// Convert a validated AXFR stream without a master-file text round trip.
    pub fn from_transfer(records: &[TransferRecord], zone_name: &ZoneName) -> Self {
        let mut parsed = Self {
            records: Vec::new(),
            soa: None,
            errors: Vec::new(),
        };
        let origin = zone_name.to_fqdn();
        for (index, record) in records.iter().enumerate() {
            if matches!(
                record.rtype,
                Rtype::RRSIG
                    | Rtype::NSEC
                    | Rtype::NSEC3
                    | Rtype::NSEC3PARAM
                    | Rtype::DNSKEY
                    | Rtype::CDS
                    | Rtype::CDNSKEY
            ) {
                continue;
            }
            if index > 0
                && index + 1 == records.len()
                && record.rtype == Rtype::SOA
                && record.rdata == records[0].rdata
            {
                continue;
            }
            let mut parser = Parser::from_ref(record.rdata.as_bytes());
            match ZoneRecordData::<_, ParsedName<_>>::parse_rdata(record.rtype, &mut parser) {
                Ok(Some(data)) if parser.remaining() == 0 => parsed.push_record(
                    &origin,
                    record.name.clone(),
                    record.rtype,
                    record.ttl,
                    &data,
                ),
                Ok(_) => parsed
                    .errors
                    .push(format!("{}: trailing RDATA bytes", record.name)),
                Err(error) => parsed.errors.push(format!("{}: {}", record.name, error)),
            }
        }
        parsed
    }

    /// Convert decoded fields into import records, preserving TXT character strings.
    fn push_record<Octs: AsRef<[u8]>, N: ToName + std::fmt::Display>(
        &mut self,
        origin_fqdn: &str,
        owner: String,
        rtype: Rtype,
        ttl_secs: u32,
        data: &ZoneRecordData<Octs, N>,
    ) {
        let record_type = match rtype {
            // Only the apex SOA supplies this zone's serial and timers.
            Rtype::SOA => {
                if to_fqdn_lowercase(&owner) != origin_fqdn {
                    self.errors.push(format!(
                        "SOA for '{}' does not belong to zone '{}'",
                        owner, origin_fqdn
                    ));
                } else if self.soa.is_some() {
                    self.errors
                        .push(format!("zone '{}' carries more than one SOA", origin_fqdn));
                } else {
                    self.soa = to_zone_file_soa(data);
                }
                return;
            }
            other => match RecordType::try_from(other) {
                Ok(record_type) => record_type,
                Err(_) => {
                    self.errors.push(format!(
                        "unsupported record type '{}' for '{}'",
                        other, owner
                    ));
                    return;
                }
            },
        };

        let ttl = Ttl::from_secs(ttl_secs);

        let (value, priority) = if record_type == RecordType::Wks {
            let mut bytes = Vec::new();
            let Ok(()) = data.compose_rdata(&mut bytes);
            match WksRecordValue::from_rdata(&bytes) {
                Ok(value) => (ZoneFileValue::Rdata(value.canonical()), None),
                Err(error) => {
                    self.errors
                        .push(format!("WKS value for '{}': {}", owner, error));
                    return;
                }
            }
        } else {
            match data {
                // Use parsed NAPTR fields because `domain` renders a root replacement as `..`.
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
                        self.errors
                            .push(format!("NAPTR value for '{}': {}", owner, e));
                        return;
                    }
                },
                ZoneRecordData::Srv(srv) => (
                    ZoneFileValue::Rdata(format!(
                        "{} {} {}",
                        srv.weight(),
                        srv.port(),
                        crate::dns::name::to_fqdn(&srv.target().to_string())
                    )),
                    Some(i32::from(srv.priority())),
                ),
                ZoneRecordData::Mx(mx) => (
                    ZoneFileValue::Rdata(crate::dns::name::to_fqdn(&mx.exchange().to_string())),
                    Some(i32::from(mx.preference())),
                ),
                ZoneRecordData::Txt(txt) => {
                    // RFC 1035, Section 3.3.14: TXT character-strings are octets.
                    match txt
                        .iter()
                        .map(std::str::from_utf8)
                        .collect::<Result<Vec<_>, _>>()
                    {
                        Ok(segments) => (
                            ZoneFileValue::Segments(
                                segments.into_iter().map(str::to_string).collect(),
                            ),
                            None,
                        ),
                        Err(_) => (
                            ZoneFileValue::Rdata(
                                txt.iter()
                                    .map(crate::dns::record::to_quoted_charstr)
                                    .collect::<Vec<_>>()
                                    .join(" "),
                            ),
                            None,
                        ),
                    }
                }
                other => (ZoneFileValue::Rdata(other.to_string()), None),
            }
        };

        self.records.push(ZoneFileRecord {
            owner_fqdn: to_fqdn_lowercase(&owner),
            record_type,
            value,
            ttl,
            priority,
        });
    }
}

/// Read an SOA record's fields, or `None` when a timer does not fit the i32
/// columns a zone stores them in.
fn to_zone_file_soa<Octs, N: ToName + std::fmt::Display>(
    data: &ZoneRecordData<Octs, N>,
) -> Option<ZoneFileSoa> {
    let ZoneRecordData::Soa(soa) = data else {
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
        minimum_ttl: Ttl::from_secs(soa.minimum().as_secs()),
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
