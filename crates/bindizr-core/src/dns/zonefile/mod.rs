//! Convert BIND master files and AXFR records into import data.

mod wks;

use std::{fmt, str};

use domain::base::ToName;
use domain::base::iana::{Class, Rtype};
use domain::base::name::ParsedName;
use domain::base::rdata::{ComposeRecordData, ParseRecordData};
use domain::dep::octseq::parse::Parser;
use domain::rdata::{Soa, ZoneRecordData};
use domain::zonefile::inplace;
use domain::zonefile::inplace::{Entry, Zonefile};
use thiserror::Error;
pub use wks::RewriteNativeRecordsError;

use crate::dns::name::ZoneName;
use crate::dns::query::TransferRecord;
use crate::dns::record::{NaptrRecordValue, ParseRecordValueError, WksRecordValue};
use crate::dns::{ConvertSoaIntervalError, LibraryError, Serial, SoaInterval, Ttl, name, record};
use crate::model::record::RecordType;

/// Directives `ParsedZoneFile::parse` prepends before handing the text to the parser.
const PRELUDE_LINES: usize = 2;

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

/// Why part of a zone file or transfer could not be imported; each is
/// reported beside the records that could.
#[derive(Debug, Error)]
pub enum ParseZoneFileError {
    #[error(transparent)]
    Rewrite(#[from] RewriteNativeRecordsError),
    #[error("unsupported record class '{class}' for '{owner}'")]
    UnsupportedClass { class: Class, owner: String },
    #[error("$INCLUDE directives are not supported")]
    Include,
    /// The scanner's typed failure, with its displayed position mapped back
    /// to the submitted text.
    #[error("failed to parse zone file: {reason}")]
    Syntax {
        reason: String,
        #[source]
        source: inplace::Error,
    },
    #[error("{owner}: trailing RDATA bytes")]
    TrailingRdata { owner: String },
    #[error("{owner}: {source}")]
    Rdata {
        owner: String,
        #[source]
        source: LibraryError,
    },
    #[error("generic RDATA for '{owner}' does not encode a {rtype} record")]
    GenericRdata { owner: String, rtype: Rtype },
    #[error("SOA for '{owner}' does not belong to zone '{zone_name}'")]
    ForeignSoa { owner: String, zone_name: String },
    #[error("zone '{zone_name}' carries more than one SOA")]
    DuplicateSoa { zone_name: String },
    #[error(
        "SOA for '{owner}' has a refresh, retry or expire past {} seconds",
        SoaInterval::MAX
    )]
    SoaIntervalTooLarge {
        owner: String,
        #[source]
        source: ConvertSoaIntervalError,
    },
    #[error("unsupported record type '{rtype}' for '{owner}'")]
    UnsupportedType { rtype: Rtype, owner: String },
    #[error("WKS value for '{owner}': {source}")]
    Wks {
        owner: String,
        #[source]
        source: ParseRecordValueError,
    },
    #[error("NAPTR value for '{owner}': {source}")]
    Naptr {
        owner: String,
        #[source]
        source: ParseRecordValueError,
    },
}

/// What a zone file yielded: its usable records, and what it could not use.
#[derive(Debug)]
pub struct ParsedZoneFile {
    pub records: Vec<ZoneFileRecord>,
    /// The apex SOA's fields, when the file carried one.
    pub soa: Option<ZoneFileSoa>,
    pub errors: Vec<ParseZoneFileError>,
}

impl ParsedZoneFile {
    /// Parse a BIND zone file using its origin and `default_ttl` for omitted TTLs.
    /// Keep the SOA separately: the zone stores its fields, not an SOA record.
    pub fn parse(content: &str, zone_name: &ZoneName, default_ttl: Ttl) -> Self {
        let content = match wks::rewrite_native_records(content) {
            Ok(content) => content,
            Err(error) => {
                return Self {
                    records: Vec::new(),
                    soa: None,
                    errors: vec![ParseZoneFileError::from(error)],
                };
            }
        };
        let origin_fqdn = zone_name.to_fqdn();

        // Feed $ORIGIN/$TTL as directives so the parser resolves relative names and
        // TTLs. PRELUDE_LINES counts them. Without a `$TTL` of its own, every omitted
        // TTL is the zone's default (RFC 2308, Section 4), not the last explicit one.
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
                        parsed.errors.push(ParseZoneFileError::UnsupportedClass {
                            class: record.class(),
                            owner: record.owner().to_string(),
                        });
                        continue;
                    }

                    parsed.push_record(
                        &origin_fqdn,
                        record.owner().to_string(),
                        record.rtype(),
                        Ttl::from(record.ttl()),
                        record.data(),
                    );
                }
                Ok(Some(Entry::Include { .. })) => {
                    parsed.errors.push(ParseZoneFileError::Include);
                }
                Ok(None) => break,
                Err(source) => {
                    parsed.errors.push(ParseZoneFileError::Syntax {
                        reason: to_input_line_message(&source),
                        source,
                    });
                    // domain documents the scanner as invalid once an entry fails.
                    break;
                }
            }
        }

        parsed
    }

    /// Convert a validated AXFR stream, its closing SOA already dropped by the
    /// client, without a master-file text round trip.
    pub fn from_transfer(records: &[TransferRecord], zone_name: &ZoneName) -> Self {
        let mut parsed = Self {
            records: Vec::new(),
            soa: None,
            errors: Vec::new(),
        };
        let origin_fqdn = zone_name.to_fqdn();

        for record in records {
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
            let mut parser = Parser::from_ref(record.rdata.as_bytes());

            match ZoneRecordData::<_, ParsedName<_>>::parse_rdata(record.rtype, &mut parser) {
                Ok(Some(data)) if parser.remaining() == 0 => parsed.push_record(
                    &origin_fqdn,
                    record.name.clone(),
                    record.rtype,
                    record.ttl,
                    &data,
                ),
                Ok(_) => parsed.errors.push(ParseZoneFileError::TrailingRdata {
                    owner: record.name.clone(),
                }),
                Err(error) => parsed.errors.push(ParseZoneFileError::Rdata {
                    owner: record.name.clone(),
                    source: Box::new(error),
                }),
            }
        }

        parsed
    }

    /// Convert decoded fields into import records, preserving TXT character strings.
    fn push_record<Octs: AsRef<[u8]>, N: ToName + fmt::Display>(
        &mut self,
        origin_fqdn: &str,
        owner: String,
        rtype: Rtype,
        ttl: Ttl,
        data: &ZoneRecordData<Octs, N>,
    ) {
        // RFC 3597, Section 5: generic `\#` RDATA of a known type is that type, so
        // decode the octets `domain` kept; WKS, which `domain` never types, reads them below.
        if let ZoneRecordData::Unknown(unknown) = data
            && rtype != Rtype::WKS
            && (rtype == Rtype::SOA || RecordType::try_from(rtype).is_ok())
        {
            let mut parser = Parser::from_ref(unknown.data().as_ref());
            return match ZoneRecordData::<_, ParsedName<_>>::parse_rdata(rtype, &mut parser) {
                Ok(Some(typed)) if parser.remaining() == 0 => {
                    self.push_record(origin_fqdn, owner, rtype, ttl, &typed);
                }
                _ => self
                    .errors
                    .push(ParseZoneFileError::GenericRdata { owner, rtype }),
            };
        }

        let record_type = match rtype {
            // Only the apex SOA supplies this zone's serial and timers.
            Rtype::SOA => {
                if name::to_fqdn_lowercase(&owner) != origin_fqdn {
                    self.errors.push(ParseZoneFileError::ForeignSoa {
                        owner,
                        zone_name: origin_fqdn.to_string(),
                    });
                } else if self.soa.is_some() {
                    self.errors.push(ParseZoneFileError::DuplicateSoa {
                        zone_name: origin_fqdn.to_string(),
                    });
                } else if let ZoneRecordData::Soa(soa) = data {
                    match to_zone_file_soa(soa) {
                        Ok(soa) => self.soa = Some(soa),
                        Err(source) => self
                            .errors
                            .push(ParseZoneFileError::SoaIntervalTooLarge { owner, source }),
                    }
                }

                return;
            }
            other => match RecordType::try_from(other) {
                Ok(record_type) => record_type,
                Err(_) => {
                    self.errors.push(ParseZoneFileError::UnsupportedType {
                        rtype: other,
                        owner,
                    });
                    return;
                }
            },
        };

        let (value, priority) = if record_type == RecordType::Wks {
            let mut bytes = Vec::new();
            let Ok(()) = data.compose_rdata(&mut bytes);

            match WksRecordValue::from_rdata(&bytes) {
                Ok(value) => (ZoneFileValue::Rdata(value.to_text()), None),
                Err(source) => {
                    self.errors.push(ParseZoneFileError::Wks { owner, source });
                    return;
                }
            }
        } else {
            // Read name fields because `domain` RDATA Display can render the root as `..`.
            match data {
                ZoneRecordData::Ns(ns) => (
                    ZoneFileValue::Rdata(name::to_fqdn(&ns.nsdname().to_string())),
                    None,
                ),
                ZoneRecordData::Cname(cname) => (
                    ZoneFileValue::Rdata(name::to_fqdn(&cname.cname().to_string())),
                    None,
                ),
                ZoneRecordData::Ptr(ptr) => (
                    ZoneFileValue::Rdata(name::to_fqdn(&ptr.ptrdname().to_string())),
                    None,
                ),
                ZoneRecordData::Dname(dname) => (
                    ZoneFileValue::Rdata(name::to_fqdn(&dname.dname().to_string())),
                    None,
                ),
                ZoneRecordData::Naptr(naptr) => match NaptrRecordValue::from_wire(
                    naptr.order(),
                    naptr.preference(),
                    naptr.flags().as_slice(),
                    naptr.services().as_slice(),
                    naptr.regexp().as_slice(),
                    &naptr.replacement().to_string(),
                )
                .map(|value| value.to_text())
                {
                    Ok(text) => (ZoneFileValue::Rdata(text), None),
                    Err(source) => {
                        self.errors
                            .push(ParseZoneFileError::Naptr { owner, source });
                        return;
                    }
                },
                ZoneRecordData::Srv(srv) => (
                    ZoneFileValue::Rdata(format!(
                        "{} {} {}",
                        srv.weight(),
                        srv.port(),
                        name::to_fqdn(&srv.target().to_string())
                    )),
                    Some(i32::from(srv.priority())),
                ),
                ZoneRecordData::Mx(mx) => (
                    ZoneFileValue::Rdata(name::to_fqdn(&mx.exchange().to_string())),
                    Some(i32::from(mx.preference())),
                ),
                ZoneRecordData::Txt(txt) => {
                    // RFC 1035, Section 3.3.14: TXT character-strings are octets.
                    match txt
                        .iter()
                        .map(str::from_utf8)
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
                                    .map(record::to_quoted_charstr)
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
            owner_fqdn: name::to_fqdn_lowercase(&owner),
            record_type,
            value,
            ttl,
            priority,
        });
    }
}

/// Read an SOA record's fields; a timer that does not fit the i32 columns a
/// zone stores them in is refused.
fn to_zone_file_soa<N: ToName + fmt::Display>(
    soa: &Soa<N>,
) -> Result<ZoneFileSoa, ConvertSoaIntervalError> {
    let interval = |value: domain::base::Ttl| SoaInterval::try_from(value.as_secs());

    // `domain` renders a parsed root name as the empty string, so both names
    // are rendered absolute: a root MNAME stays `.` (RFC 2181, Section 11).
    Ok(ZoneFileSoa {
        mname: name::to_fqdn(&soa.mname().to_string()),
        // The mailbox is rendered in its SOA form (`admin.example.com.`); the
        // service turns it back into an address.
        rname: name::to_fqdn(&soa.rname().to_string()),
        serial: Serial::from(soa.serial().into_int()),
        refresh: interval(soa.refresh())?,
        retry: interval(soa.retry())?,
        expire: interval(soa.expire())?,
        minimum_ttl: Ttl::from(soa.minimum()),
    })
}

/// Restate a parser error in the submitted text's line numbering. `Error` keeps
/// its position private, so its `{line}:{col}: {reason}` rendering is all there is.
fn to_input_line_message(error: &inplace::Error) -> String {
    let message = error.to_string();

    match message.split_once(':') {
        Some((line, rest)) => match line.parse::<usize>() {
            Ok(line) if line > PRELUDE_LINES => format!("{}:{rest}", line - PRELUDE_LINES),
            _ => message,
        },
        None => message,
    }
}

#[cfg(test)]
mod tests;
