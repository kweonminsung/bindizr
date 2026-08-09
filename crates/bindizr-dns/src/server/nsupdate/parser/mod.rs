use std::fmt;

use bindizr_core::dns::name::escape_presentation_label;
use domain::{
    base::{
        Message,
        iana::{Class, Opcode, Rtype},
        name::ParsedName,
    },
    dep::octseq::parse::Parser,
    rdata::tsig::Tsig,
};

/// Fixed length of a DNS message header, in bytes.
const DNS_HEADER_LEN: usize = 12;

#[derive(Debug, Clone)]
pub(super) struct UpdateRequest {
    pub zone_name: String,
    pub prerequisites: Vec<UpdateRecord>,
    pub updates: Vec<UpdateRecord>,
    pub tsig: Option<TsigRecord>,
}

/// One RR from the prerequisite or update section. `rdata_start` locates the
/// rdata in the original message so compressed names inside it can be decoded
/// lazily by the update flow.
#[derive(Debug, Clone)]
pub(super) struct UpdateRecord {
    pub name: String,
    pub rr_type: Rtype,
    pub class: Class,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub rdata_start: usize,
}

/// The request's TSIG record, reduced to what the update flow needs: the key
/// name for the DB lookup and the fudge echoed in the response. Cryptographic
/// validation re-reads the full record via `domain::tsig`; parsing here still
/// rejects structurally invalid TSIG RRs with FORMERR (RFC 8945, Section 5.2) before
/// that happens.
#[derive(Debug, Clone)]
pub(super) struct TsigRecord {
    pub name: String,
    pub fudge: u16,
}

#[derive(Debug)]
pub(super) enum ParseError {
    TooShort,
    InvalidOpcode,
    InvalidHeader,
    InvalidZoneSection,
    InvalidName,
    InvalidRr,
    InvalidTsig,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "DNS message is too short"),
            ParseError::InvalidOpcode => write!(f, "Not a DNS UPDATE opcode"),
            ParseError::InvalidHeader => write!(f, "Invalid DNS UPDATE header"),
            ParseError::InvalidZoneSection => write!(f, "Invalid DNS UPDATE zone section"),
            ParseError::InvalidName => write!(f, "Invalid compressed domain name"),
            ParseError::InvalidRr => write!(f, "Invalid resource record in UPDATE section"),
            ParseError::InvalidTsig => write!(f, "Invalid TSIG resource record"),
        }
    }
}

pub(super) fn parse_update_request(data: &[u8]) -> Result<UpdateRequest, ParseError> {
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
    let zone_name = presentation_name(&zone)?;

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

fn parse_rr(parser: &mut Parser<'_, [u8]>, data: &[u8]) -> Result<UpdateRecord, ParseError> {
    let name = ParsedName::parse(parser).map_err(|_| ParseError::InvalidName)?;
    let name = presentation_name(&name)?;

    let rr_type = Rtype::from_int(parser.parse_u16_be().map_err(|_| ParseError::InvalidRr)?);
    let class = Class::from_int(parser.parse_u16_be().map_err(|_| ParseError::InvalidRr)?);
    let ttl = parser.parse_u32_be().map_err(|_| ParseError::InvalidRr)?;
    let rdlen = parser.parse_u16_be().map_err(|_| ParseError::InvalidRr)? as usize;

    let rdata_start = parser.pos();
    parser.advance(rdlen).map_err(|_| ParseError::InvalidRr)?;

    Ok(UpdateRecord {
        name,
        rr_type,
        class,
        ttl,
        rdata: data[rdata_start..rdata_start + rdlen].to_vec(),
        rdata_start,
    })
}

fn parse_additional_section(
    parser: &mut Parser<'_, [u8]>,
    count: usize,
) -> Result<Option<TsigRecord>, ParseError> {
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
) -> Result<TsigRecord, ParseError> {
    let class = Class::from_int(parser.parse_u16_be().map_err(|_| ParseError::InvalidTsig)?);
    let ttl = parser.parse_u32_be().map_err(|_| ParseError::InvalidTsig)?;
    let rdlen = parser.parse_u16_be().map_err(|_| ParseError::InvalidTsig)? as usize;

    if class != Class::ANY || ttl != 0 {
        return Err(ParseError::InvalidTsig);
    }

    let mut rdata = parser
        .parse_parser(rdlen)
        .map_err(|_| ParseError::InvalidTsig)?;
    let record = Tsig::parse(&mut rdata).map_err(|_| ParseError::InvalidTsig)?;
    if rdata.remaining() != 0 {
        return Err(ParseError::InvalidTsig);
    }

    Ok(TsigRecord {
        name: presentation_name(owner)?,
        fudge: record.fudge(),
    })
}

/// Renders a parsed name the way the update flow stores names: labels joined
/// with '.', trailing dot, and a `.` or `\` inside a label escaped so the label
/// cannot read as a label boundary downstream nor re-split on the way to wire.
pub(super) fn presentation_name(name: &ParsedName<&[u8]>) -> Result<String, ParseError> {
    let mut out = String::new();

    for label in name.iter() {
        if label.is_root() {
            break;
        }

        let text = std::str::from_utf8(label.as_slice()).map_err(|_| ParseError::InvalidName)?;
        out.push_str(&escape_presentation_label(text));
        out.push('.');
    }

    if out.is_empty() {
        out.push('.');
    }

    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests;
