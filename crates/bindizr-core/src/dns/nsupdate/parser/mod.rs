use domain::{
    base::{
        Message,
        iana::{Class, Opcode, Rtype},
        name::ParsedName,
    },
    dep::octseq::parse::Parser,
    rdata::{A, Aaaa, Mx, Srv, Txt, tsig::Tsig},
};
use thiserror::Error;

use crate::{
    dns::{
        name::labels_to_presentation,
        record::{NaptrRecordValue, ParseRecordValueError, TxtRecordValue},
    },
    model::record::{ParseRecordTypeError, RecordType},
};

/// Fixed length of a DNS message header, in bytes.
const DNS_HEADER_LEN: usize = 12;

/// A parsed UPDATE message: its zone, prerequisites, updates, and TSIG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    pub zone_name: String,
    pub prerequisites: Vec<UpdateRecord>,
    pub updates: Vec<UpdateRecord>,
    pub tsig: Option<TsigRecord>,
}

/// One record from the prerequisite or update section. `rdata_start` locates the
/// rdata in the original message so compressed names inside it can be decoded
/// lazily by the update flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRecord {
    pub name: String,
    pub record_type: Rtype,
    pub class: Class,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub rdata_start: usize,
}

/// TSIG key name for lookup and fudge for the response; `domain::tsig` verifies the full record.
/// Parsing rejects malformed TSIG records with FORMERR (RFC 8945, Section 5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigRecord {
    pub name: String,
    pub fudge: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseUpdateError {
    #[error("DNS message is too short")]
    TooShort,
    #[error("not a DNS UPDATE opcode")]
    InvalidOpcode,
    #[error("invalid DNS UPDATE header")]
    InvalidHeader,
    #[error("invalid DNS UPDATE zone section")]
    InvalidZoneSection,
    #[error("invalid compressed domain name")]
    InvalidName,
    #[error("invalid record in UPDATE section")]
    InvalidRecord,
    #[error("invalid TSIG record")]
    InvalidTsig,
    /// The record's RDATA does not parse as its type, or does not fill RDLENGTH.
    #[error("invalid {record_type} rdata")]
    Rdata { record_type: String },
    /// A name inside the RDATA does not read back into presentation form.
    #[error("invalid {record_type} rdata: {source}")]
    RdataName {
        record_type: String,
        #[source]
        source: Box<ParseUpdateError>,
    },
    /// The `domain` TXT reader's error implements no `Error`, so its text
    /// is what is kept.
    #[error("invalid TXT rdata: {reason}")]
    TxtRdata { reason: String },
    #[error("invalid TXT rdata: {0}")]
    TxtValue(#[source] ParseRecordValueError),
    #[error(transparent)]
    RecordType(#[from] ParseRecordTypeError),
    #[error(transparent)]
    Value(#[from] ParseRecordValueError),
}

impl UpdateRequest {
    /// Parse the zone, prerequisites, updates, and TSIG from an UPDATE message.
    pub fn parse(data: &[u8]) -> Result<Self, ParseUpdateError> {
        let message = Message::from_octets(data).map_err(|_| ParseUpdateError::TooShort)?;

        if message.header().opcode() != Opcode::UPDATE {
            return Err(ParseUpdateError::InvalidOpcode);
        }

        let counts = message.header_counts();
        if counts.qdcount() != 1 {
            return Err(ParseUpdateError::InvalidHeader);
        }

        let mut parser = Parser::from_ref(data);
        parser
            .advance(DNS_HEADER_LEN)
            .map_err(|_| ParseUpdateError::TooShort)?;

        // The single question identifies the update zone and must carry SOA/IN.
        let zone = ParsedName::parse(&mut parser).map_err(|_| ParseUpdateError::InvalidName)?;
        let ztype = parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidZoneSection)?;
        let zclass = parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidZoneSection)?;

        if Rtype::from_int(ztype) != Rtype::SOA || Class::from_int(zclass) != Class::IN {
            return Err(ParseUpdateError::InvalidZoneSection);
        }
        let zone_name = to_presentation_name(&zone)?;

        // UPDATE uses the answer count for prerequisites and the authority count
        // for changes; these are not ordinary response sections.
        let mut prerequisites = Vec::with_capacity(counts.ancount() as usize);
        for _ in 0..counts.ancount() {
            prerequisites.push(parse_record(&mut parser, data)?);
        }

        let mut updates = Vec::with_capacity(counts.nscount() as usize);
        for _ in 0..counts.nscount() {
            updates.push(parse_record(&mut parser, data)?);
        }

        let tsig = parse_additional_section(&mut parser, counts.arcount() as usize)?;

        if parser.remaining() != 0 {
            return Err(ParseUpdateError::InvalidHeader);
        }

        Ok(UpdateRequest {
            zone_name,
            prerequisites,
            updates,
            tsig,
        })
    }
}

/// Read one update record from the DNS wire message.
fn parse_record(
    parser: &mut Parser<'_, [u8]>,
    data: &[u8],
) -> Result<UpdateRecord, ParseUpdateError> {
    let name = ParsedName::parse(parser).map_err(|_| ParseUpdateError::InvalidName)?;
    let name = to_presentation_name(&name)?;

    let record_type = Rtype::from_int(
        parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidRecord)?,
    );
    let class = Class::from_int(
        parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidRecord)?,
    );
    let ttl = parser
        .parse_u32_be()
        .map_err(|_| ParseUpdateError::InvalidRecord)?;
    let rdlen = parser
        .parse_u16_be()
        .map_err(|_| ParseUpdateError::InvalidRecord)? as usize;

    let rdata_start = parser.pos();
    parser
        .advance(rdlen)
        .map_err(|_| ParseUpdateError::InvalidRecord)?;

    Ok(UpdateRecord {
        name,
        record_type,
        class,
        ttl,
        rdata: data[rdata_start..rdata_start + rdlen].to_vec(),
        rdata_start,
    })
}

/// Validate additional records and locate the request's TSIG.
fn parse_additional_section(
    parser: &mut Parser<'_, [u8]>,
    count: usize,
) -> Result<Option<TsigRecord>, ParseUpdateError> {
    let mut tsig = None;

    for index in 0..count {
        let owner = ParsedName::parse(parser).map_err(|_| ParseUpdateError::InvalidName)?;
        let record_type = Rtype::from_int(
            parser
                .parse_u16_be()
                .map_err(|_| ParseUpdateError::InvalidRecord)?,
        );

        if record_type == Rtype::TSIG {
            if tsig.is_some() || index + 1 != count {
                return Err(ParseUpdateError::InvalidTsig);
            }

            tsig = Some(parse_tsig_record(parser, &owner)?);
        } else {
            parser
                .parse_u16_be()
                .map_err(|_| ParseUpdateError::InvalidRecord)?; // CLASS
            parser
                .parse_u32_be()
                .map_err(|_| ParseUpdateError::InvalidRecord)?; // TTL
            let rdlen = parser
                .parse_u16_be()
                .map_err(|_| ParseUpdateError::InvalidRecord)? as usize;
            parser
                .advance(rdlen)
                .map_err(|_| ParseUpdateError::InvalidRecord)?;
        }
    }

    Ok(tsig)
}

/// Parses a TSIG record from its CLASS field on (owner and TYPE already consumed).
fn parse_tsig_record(
    parser: &mut Parser<'_, [u8]>,
    owner: &ParsedName<&[u8]>,
) -> Result<TsigRecord, ParseUpdateError> {
    let class = Class::from_int(
        parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidTsig)?,
    );
    let ttl = parser
        .parse_u32_be()
        .map_err(|_| ParseUpdateError::InvalidTsig)?;
    let rdlen = parser
        .parse_u16_be()
        .map_err(|_| ParseUpdateError::InvalidTsig)? as usize;

    if class != Class::ANY || ttl != 0 {
        return Err(ParseUpdateError::InvalidTsig);
    }

    let mut rdata = parser
        .parse_parser(rdlen)
        .map_err(|_| ParseUpdateError::InvalidTsig)?;
    let tsig = Tsig::parse(&mut rdata).map_err(|_| ParseUpdateError::InvalidTsig)?;
    if rdata.remaining() != 0 {
        return Err(ParseUpdateError::InvalidTsig);
    }

    Ok(TsigRecord {
        name: to_presentation_name(owner)?,
        fudge: tsig.fudge(),
    })
}

/// Renders a parsed name in presentation form, escaping a `.` or `\` inside a
/// label so the text decodes back to the same labels (RFC 1035, Section 5.1).
fn to_presentation_name(name: &ParsedName<&[u8]>) -> Result<String, ParseUpdateError> {
    let mut labels = Vec::new();

    for label in name.iter() {
        if label.is_root() {
            break;
        }

        let text =
            std::str::from_utf8(label.as_slice()).map_err(|_| ParseUpdateError::InvalidName)?;
        labels.push(text.to_string());
    }

    if labels.is_empty() {
        return Ok(".".to_string());
    }

    Ok(format!("{}.", labels_to_presentation(&labels)))
}

/// A deletion whose shape RFC 2136, Section 2.5 does not allow.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DeleteShapeError {
    #[error("delete update TTL must be 0")]
    NonzeroTtl,
    #[error("ANY-class delete must have empty rdata")]
    AnyClassRdata,
    #[error("NONE-class delete must specify record type")]
    NoneClassTypeAny,
    #[error("NONE-class delete must specify rdata")]
    NoneClassNoRdata,
}

impl UpdateRecord {
    /// Check the TTL, type, and RDATA a deletion of this record's class must
    /// carry: an ANY-class delete names a record set (RFC 2136, Section
    /// 2.5.2), a NONE-class delete one record (Section 2.5.4).
    pub fn validate_delete_shape(&self) -> Result<(), DeleteShapeError> {
        if self.ttl != 0 {
            return Err(DeleteShapeError::NonzeroTtl);
        }
        match self.class {
            Class::ANY if !self.rdata.is_empty() => Err(DeleteShapeError::AnyClassRdata),
            Class::NONE if self.record_type == Rtype::ANY => {
                Err(DeleteShapeError::NoneClassTypeAny)
            }
            Class::NONE if self.rdata.is_empty() => Err(DeleteShapeError::NoneClassNoRdata),
            _ => Ok(()),
        }
    }

    /// Decode an update record's wire data into its typed value.
    fn parse_rdata<'a, T>(
        &self,
        message: &'a [u8],
        what: &str,
        parse: impl FnOnce(&mut Parser<'a, [u8]>) -> Option<T>,
    ) -> Result<T, ParseUpdateError> {
        let refused = || ParseUpdateError::Rdata {
            record_type: what.to_string(),
        };

        // Compression pointers address the whole message, not the RDATA slice.
        let mut parser = Parser::from_ref(message);
        parser.advance(self.rdata_start).map_err(|_| refused())?;
        let value = parse(&mut parser).ok_or_else(refused)?;

        // A type parser must consume exactly RDLENGTH, without borrowing the next record.
        if parser.pos() != self.rdata_start + self.rdata.len() {
            return Err(refused());
        }

        Ok(value)
    }

    /// Decode this record into stored columns. `message` must be the original
    /// UPDATE message: compressed RDATA names refer to offsets within it.
    pub fn to_record_value(
        &self,
        message: &[u8],
    ) -> Result<(RecordType, String, Option<i32>), ParseUpdateError> {
        match RecordType::try_from(self.record_type)? {
            RecordType::A => {
                let data = self.parse_rdata(message, "A", |parser| A::parse(parser).ok())?;
                Ok((RecordType::A, data.addr().to_string(), None))
            }
            RecordType::Aaaa => {
                let data = self.parse_rdata(message, "AAAA", |parser| Aaaa::parse(parser).ok())?;
                Ok((RecordType::Aaaa, data.addr().to_string(), None))
            }
            record_type @ (RecordType::Cname
            | RecordType::Dname
            | RecordType::Ns
            | RecordType::Ptr) => {
                let name = self.parse_rdata(message, record_type.as_str(), |parser| {
                    ParsedName::parse(parser).ok()
                })?;
                let value =
                    to_presentation_name(&name).map_err(|e| ParseUpdateError::RdataName {
                        record_type: record_type.as_str().to_string(),
                        source: Box::new(e),
                    })?;
                Ok((record_type, value, None))
            }
            RecordType::Txt => {
                let data = Txt::from_octets(self.rdata.as_slice()).map_err(|e| {
                    ParseUpdateError::TxtRdata {
                        reason: e.to_string(),
                    }
                })?;
                // TXT values must be valid UTF-8 (a project-wide rule), so reject
                // non-UTF-8 character-strings even though the wire allows them.
                for charstr in data.iter_charstrs() {
                    if std::str::from_utf8(charstr.as_slice()).is_err() {
                        return Err(ParseUpdateError::Rdata {
                            record_type: "TXT".to_string(),
                        });
                    }
                }
                let value = TxtRecordValue::from_rdata(&self.rdata)
                    .map_err(ParseUpdateError::TxtValue)?
                    .to_presentation();
                Ok((RecordType::Txt, value, None))
            }
            RecordType::Caa => {
                let data = self.parse_rdata(message, "CAA", |parser| {
                    domain::rdata::Caa::parse(parser).ok()
                })?;
                Ok((RecordType::Caa, data.to_string(), None))
            }
            RecordType::Ds => {
                let data = self.parse_rdata(message, "DS", |parser| {
                    domain::rdata::Ds::parse(parser).ok()
                })?;
                Ok((RecordType::Ds, data.to_string(), None))
            }
            RecordType::Naptr => {
                let data = self.parse_rdata(message, "NAPTR", |parser| {
                    domain::rdata::Naptr::parse(parser).ok()
                })?;
                let replacement = to_presentation_name(data.replacement()).map_err(|e| {
                    ParseUpdateError::RdataName {
                        record_type: "NAPTR".to_string(),
                        source: Box::new(e),
                    }
                })?;
                let value = NaptrRecordValue::from_wire(
                    data.order(),
                    data.preference(),
                    data.flags().as_slice(),
                    data.services().as_slice(),
                    data.regexp().as_slice(),
                    &replacement,
                )?
                .canonical();
                Ok((RecordType::Naptr, value, None))
            }
            RecordType::Sshfp => {
                let data = self.parse_rdata(message, "SSHFP", |parser| {
                    domain::rdata::Sshfp::parse(parser).ok()
                })?;
                Ok((RecordType::Sshfp, data.to_string(), None))
            }
            RecordType::Tlsa => {
                let data = self.parse_rdata(message, "TLSA", |parser| {
                    domain::rdata::Tlsa::parse(parser).ok()
                })?;
                Ok((RecordType::Tlsa, data.to_string(), None))
            }
            RecordType::Mx => {
                let data = self.parse_rdata(message, "MX", |parser| Mx::parse(parser).ok())?;
                let host = to_presentation_name(data.exchange()).map_err(|e| {
                    ParseUpdateError::RdataName {
                        record_type: "MX".to_string(),
                        source: Box::new(e),
                    }
                })?;
                Ok((RecordType::Mx, host, Some(i32::from(data.preference()))))
            }
            RecordType::Srv => {
                let data = self.parse_rdata(message, "SRV", |parser| Srv::parse(parser).ok())?;
                let target = to_presentation_name(data.target()).map_err(|e| {
                    ParseUpdateError::RdataName {
                        record_type: "SRV".to_string(),
                        source: Box::new(e),
                    }
                })?;
                // Priority lives in its own column, so the value holds the rest.
                Ok((
                    RecordType::Srv,
                    format!("{} {} {}", data.weight(), data.port(), target),
                    Some(i32::from(data.priority())),
                ))
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
