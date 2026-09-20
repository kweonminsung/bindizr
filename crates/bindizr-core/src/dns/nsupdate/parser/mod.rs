use std::fmt;

use domain::{
    base::{
        Message,
        iana::{Class, Opcode, Rtype},
        name::ParsedName,
    },
    dep::octseq::parse::Parser,
    rdata::{A, Aaaa, Mx, Srv, Txt, tsig::Tsig},
};

use crate::{
    dns::{
        name::labels_to_presentation,
        record::{NaptrRecordValue, TxtRecordValue},
    },
    model::record::RecordType,
};

/// Fixed length of a DNS message header, in bytes.
const DNS_HEADER_LEN: usize = 12;

/// A parsed UPDATE message: its zone, prerequisites, updates, and TSIG.
#[derive(Debug, Clone)]
pub struct UpdateRequest {
    pub zone_name: String,
    pub prerequisites: Vec<UpdateRr>,
    pub updates: Vec<UpdateRr>,
    pub tsig: Option<TsigRr>,
}

/// One RR from the prerequisite or update section. `rdata_start` locates the
/// rdata in the original message so compressed names inside it can be decoded
/// lazily by the update flow.
#[derive(Debug, Clone)]
pub struct UpdateRr {
    pub name: String,
    pub rr_type: Rtype,
    pub class: Class,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub rdata_start: usize,
}

/// The request's TSIG RR, reduced to what the update flow needs: the key
/// name for the DB lookup and the fudge echoed in the response. Cryptographic
/// validation re-reads the full RR via `domain::tsig`; parsing here still
/// rejects structurally invalid TSIG RRs with FORMERR (RFC 8945, Section 5.2) before
/// that happens.
#[derive(Debug, Clone)]
pub struct TsigRr {
    pub name: String,
    pub fudge: u16,
}

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    InvalidOpcode,
    InvalidHeader,
    InvalidZoneSection,
    InvalidName,
    InvalidRr,
    InvalidTsig,
}

impl fmt::Display for ParseError {
    /// Write the parse error in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "DNS message is too short"),
            ParseError::InvalidOpcode => write!(f, "Not a DNS UPDATE opcode"),
            ParseError::InvalidHeader => write!(f, "Invalid DNS UPDATE header"),
            ParseError::InvalidZoneSection => write!(f, "Invalid DNS UPDATE zone section"),
            ParseError::InvalidName => write!(f, "Invalid compressed domain name"),
            ParseError::InvalidRr => write!(f, "Invalid record in UPDATE section"),
            ParseError::InvalidTsig => write!(f, "Invalid TSIG record"),
        }
    }
}

impl UpdateRequest {
    /// Parse the zone, prerequisites, updates, and TSIG from an UPDATE message.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let message = Message::from_octets(data).map_err(|_| ParseError::TooShort)?;

        if message.header().opcode() != Opcode::UPDATE {
            return Err(ParseError::InvalidOpcode);
        }

        let counts = message.header_counts();
        if counts.qdcount() != 1 {
            return Err(ParseError::InvalidHeader);
        }

        let mut parser = Parser::from_ref(data);
        parser
            .advance(DNS_HEADER_LEN)
            .map_err(|_| ParseError::TooShort)?;

        // The single question identifies the update zone and must carry SOA/IN.
        let zone = ParsedName::parse(&mut parser).map_err(|_| ParseError::InvalidName)?;
        let ztype = parser
            .parse_u16_be()
            .map_err(|_| ParseError::InvalidZoneSection)?;
        let zclass = parser
            .parse_u16_be()
            .map_err(|_| ParseError::InvalidZoneSection)?;

        if Rtype::from_int(ztype) != Rtype::SOA || Class::from_int(zclass) != Class::IN {
            return Err(ParseError::InvalidZoneSection);
        }
        let zone_name = to_presentation_name(&zone)?;

        // UPDATE uses the answer count for prerequisites and the authority count
        // for changes; these are not ordinary response sections.
        let mut prerequisites = Vec::with_capacity(counts.ancount() as usize);
        for _ in 0..counts.ancount() {
            prerequisites.push(parse_rr(&mut parser, data)?);
        }

        let mut updates = Vec::with_capacity(counts.nscount() as usize);
        for _ in 0..counts.nscount() {
            updates.push(parse_rr(&mut parser, data)?);
        }

        let tsig = parse_additional_section(&mut parser, counts.arcount() as usize)?;

        if parser.remaining() != 0 {
            return Err(ParseError::InvalidHeader);
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
fn parse_rr(parser: &mut Parser<'_, [u8]>, data: &[u8]) -> Result<UpdateRr, ParseError> {
    let name = ParsedName::parse(parser).map_err(|_| ParseError::InvalidName)?;
    let name = to_presentation_name(&name)?;

    let rr_type = Rtype::from_int(parser.parse_u16_be().map_err(|_| ParseError::InvalidRr)?);
    let class = Class::from_int(parser.parse_u16_be().map_err(|_| ParseError::InvalidRr)?);
    let ttl = parser.parse_u32_be().map_err(|_| ParseError::InvalidRr)?;
    let rdlen = parser.parse_u16_be().map_err(|_| ParseError::InvalidRr)? as usize;

    let rdata_start = parser.pos();
    parser.advance(rdlen).map_err(|_| ParseError::InvalidRr)?;

    Ok(UpdateRr {
        name,
        rr_type,
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
) -> Result<Option<TsigRr>, ParseError> {
    let mut tsig = None;

    for index in 0..count {
        let owner = ParsedName::parse(parser).map_err(|_| ParseError::InvalidName)?;
        let rr_type = Rtype::from_int(parser.parse_u16_be().map_err(|_| ParseError::InvalidRr)?);

        if rr_type == Rtype::TSIG {
            if tsig.is_some() || index + 1 != count {
                return Err(ParseError::InvalidTsig);
            }

            tsig = Some(parse_tsig_rr(parser, &owner)?);
        } else {
            parser.parse_u16_be().map_err(|_| ParseError::InvalidRr)?; // CLASS
            parser.parse_u32_be().map_err(|_| ParseError::InvalidRr)?; // TTL
            let rdlen = parser.parse_u16_be().map_err(|_| ParseError::InvalidRr)? as usize;
            parser.advance(rdlen).map_err(|_| ParseError::InvalidRr)?;
        }
    }

    Ok(tsig)
}

/// Parses a TSIG RR from its CLASS field on (owner and TYPE already consumed).
fn parse_tsig_rr(
    parser: &mut Parser<'_, [u8]>,
    owner: &ParsedName<&[u8]>,
) -> Result<TsigRr, ParseError> {
    let class = Class::from_int(parser.parse_u16_be().map_err(|_| ParseError::InvalidTsig)?);
    let ttl = parser.parse_u32_be().map_err(|_| ParseError::InvalidTsig)?;
    let rdlen = parser.parse_u16_be().map_err(|_| ParseError::InvalidTsig)? as usize;

    if class != Class::ANY || ttl != 0 {
        return Err(ParseError::InvalidTsig);
    }

    let mut rdata = parser
        .parse_parser(rdlen)
        .map_err(|_| ParseError::InvalidTsig)?;
    let tsig = Tsig::parse(&mut rdata).map_err(|_| ParseError::InvalidTsig)?;
    if rdata.remaining() != 0 {
        return Err(ParseError::InvalidTsig);
    }

    Ok(TsigRr {
        name: to_presentation_name(owner)?,
        fudge: tsig.fudge(),
    })
}

/// Renders a parsed name in presentation form, escaping a `.` or `\` inside a
/// label so the text decodes back to the same labels (RFC 1035, Section 5.1).
fn to_presentation_name(name: &ParsedName<&[u8]>) -> Result<String, ParseError> {
    let mut labels = Vec::new();

    for label in name.iter() {
        if label.is_root() {
            break;
        }

        let text = std::str::from_utf8(label.as_slice()).map_err(|_| ParseError::InvalidName)?;
        labels.push(text.to_string());
    }

    if labels.is_empty() {
        return Ok(".".to_string());
    }

    Ok(format!("{}.", labels_to_presentation(&labels)))
}

impl UpdateRr {
    /// Decode an update record's wire data into its typed value.
    fn parse_rdata<'a, T>(
        &self,
        message: &'a [u8],
        what: &str,
        parse: impl FnOnce(&mut Parser<'a, [u8]>) -> Option<T>,
    ) -> Result<T, String> {
        let refused = || format!("invalid {} rdata", what);

        // Compression pointers address the whole message, not the RDATA slice.
        let mut parser = Parser::from_ref(message);
        parser.advance(self.rdata_start).map_err(|_| refused())?;
        let value = parse(&mut parser).ok_or_else(refused)?;

        // A type parser must consume exactly RDLENGTH, without borrowing the next RR.
        if parser.pos() != self.rdata_start + self.rdata.len() {
            return Err(refused());
        }

        Ok(value)
    }

    /// Decode this RR into stored columns. `message` must be the original
    /// UPDATE message: compressed RDATA names refer to offsets within it.
    pub fn to_record_value(
        &self,
        message: &[u8],
    ) -> Result<(RecordType, String, Option<i32>), String> {
        match RecordType::try_from(self.rr_type)? {
            RecordType::A => {
                let data = self.parse_rdata(message, "A", |parser| A::parse(parser).ok())?;
                Ok((RecordType::A, data.addr().to_string(), None))
            }
            RecordType::AAAA => {
                let data = self.parse_rdata(message, "AAAA", |parser| Aaaa::parse(parser).ok())?;
                Ok((RecordType::AAAA, data.addr().to_string(), None))
            }
            record_type @ (RecordType::CNAME
            | RecordType::DNAME
            | RecordType::NS
            | RecordType::PTR) => {
                let name = self.parse_rdata(message, record_type.as_str(), |parser| {
                    ParsedName::parse(parser).ok()
                })?;
                let value = to_presentation_name(&name)
                    .map_err(|e| format!("invalid {} rdata: {}", record_type.as_str(), e))?;
                Ok((record_type, value, None))
            }
            RecordType::TXT => {
                let data = Txt::from_octets(self.rdata.as_slice())
                    .map_err(|e| format!("invalid TXT rdata: {}", e))?;
                // TXT values must be valid UTF-8 (a project-wide rule), so reject
                // non-UTF-8 character-strings even though the wire allows them.
                for charstr in data.iter_charstrs() {
                    if std::str::from_utf8(charstr.as_slice()).is_err() {
                        return Err("invalid TXT rdata".to_string());
                    }
                }
                let value = TxtRecordValue::from_rdata(&self.rdata)
                    .map_err(|e| format!("invalid TXT rdata: {}", e))?
                    .to_presentation();
                Ok((RecordType::TXT, value, None))
            }
            RecordType::CAA => {
                let data = self.parse_rdata(message, "CAA", |parser| {
                    domain::rdata::Caa::parse(parser).ok()
                })?;
                Ok((RecordType::CAA, data.to_string(), None))
            }
            RecordType::DS => {
                let data = self.parse_rdata(message, "DS", |parser| {
                    domain::rdata::Ds::parse(parser).ok()
                })?;
                Ok((RecordType::DS, data.to_string(), None))
            }
            RecordType::NAPTR => {
                let data = self.parse_rdata(message, "NAPTR", |parser| {
                    domain::rdata::Naptr::parse(parser).ok()
                })?;
                let replacement = to_presentation_name(data.replacement())
                    .map_err(|e| format!("invalid NAPTR rdata: {}", e))?;
                let value = NaptrRecordValue::from_wire(
                    data.order(),
                    data.preference(),
                    data.flags().as_slice(),
                    data.services().as_slice(),
                    data.regexp().as_slice(),
                    &replacement,
                )?
                .canonical();
                Ok((RecordType::NAPTR, value, None))
            }
            RecordType::SSHFP => {
                let data = self.parse_rdata(message, "SSHFP", |parser| {
                    domain::rdata::Sshfp::parse(parser).ok()
                })?;
                Ok((RecordType::SSHFP, data.to_string(), None))
            }
            RecordType::TLSA => {
                let data = self.parse_rdata(message, "TLSA", |parser| {
                    domain::rdata::Tlsa::parse(parser).ok()
                })?;
                Ok((RecordType::TLSA, data.to_string(), None))
            }
            RecordType::MX => {
                let data = self.parse_rdata(message, "MX", |parser| Mx::parse(parser).ok())?;
                let host = to_presentation_name(data.exchange())
                    .map_err(|e| format!("invalid MX rdata: {}", e))?;
                Ok((RecordType::MX, host, Some(i32::from(data.preference()))))
            }
            RecordType::SRV => {
                let data = self.parse_rdata(message, "SRV", |parser| Srv::parse(parser).ok())?;
                let target = to_presentation_name(data.target())
                    .map_err(|e| format!("invalid SRV rdata: {}", e))?;
                // Priority lives in its own column, so the value holds the rest.
                Ok((
                    RecordType::SRV,
                    format!("{} {} {}", data.weight(), data.port(), target),
                    Some(i32::from(data.priority())),
                ))
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
