mod record;

use domain::{
    base::{
        Message,
        iana::{Class, Opcode, Rtype},
        name::ParsedName,
    },
    dep::octseq::parse::Parser,
    rdata::tsig::Tsig,
};
pub use record::{UpdateRecord, ValidateUpdateShapeError};
use thiserror::Error;

use crate::{
    dns::{
        message::Edns,
        name::labels_to_presentation,
        record::{ParseRdataError, ParseRecordValueError},
        tsig::is_mac_size_in_bounds,
    },
    model::record::ParseRecordTypeError,
};

/// Fixed length of a DNS message header, in bytes.
const DNS_HEADER_LEN: usize = 12;

/// A parsed UPDATE message: its zone, prerequisites, updates, TSIG, and OPT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    pub zone_name: String,
    pub zone_class: Class,
    pub prerequisites: Vec<UpdateRecord>,
    pub updates: Vec<UpdateRecord>,
    pub tsig: Option<TsigRecord>,
    pub edns: Edns,
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
    #[error("invalid prerequisite rdata: {0}")]
    PrerequisiteRdata(#[from] ParseRdataError),
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

        // RFC 2136, Section 3.1.1 requires SOA; authority over ZCLASS is
        // decided by the service, not by the wire parser.
        let zone = ParsedName::parse(&mut parser).map_err(|_| ParseUpdateError::InvalidName)?;
        let ztype = parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidZoneSection)?;
        let zclass = parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidZoneSection)?;

        if Rtype::from_int(ztype) != Rtype::SOA {
            return Err(ParseUpdateError::InvalidZoneSection);
        }
        let zone_name = to_presentation_name(&zone)?;

        // UPDATE uses the answer count for prerequisites and the authority count
        // for changes; these are not ordinary response sections.
        let mut prerequisites = Vec::with_capacity(usize::from(counts.ancount()));
        for _ in 0..counts.ancount() {
            prerequisites.push(parse_record(&mut parser, data)?);
        }

        let mut updates = Vec::with_capacity(usize::from(counts.nscount()));
        for _ in 0..counts.nscount() {
            updates.push(parse_record(&mut parser, data)?);
        }

        let tsig = parse_additional_section(&mut parser, usize::from(counts.arcount()))?;

        if parser.remaining() != 0 {
            return Err(ParseUpdateError::InvalidHeader);
        }

        Ok(UpdateRequest {
            zone_name,
            zone_class: Class::from_int(zclass),
            prerequisites,
            updates,
            tsig,
            edns: Edns::from_message(&message),
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
    let rdlen = usize::from(
        parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidRecord)?,
    );

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
            // CLASS and TTL are opaque here; EDNS metadata uses the shared decoder.
            parser
                .advance(6)
                .map_err(|_| ParseUpdateError::InvalidRecord)?;
            let rdlen = usize::from(
                parser
                    .parse_u16_be()
                    .map_err(|_| ParseUpdateError::InvalidRecord)?,
            );
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
    let rdlen = usize::from(
        parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidTsig)?,
    );

    if class != Class::ANY || ttl != 0 {
        return Err(ParseUpdateError::InvalidTsig);
    }

    let mut rdata = parser
        .parse_parser(rdlen)
        .map_err(|_| ParseUpdateError::InvalidTsig)?;
    let tsig = Tsig::parse(&mut rdata).map_err(|_| ParseUpdateError::InvalidTsig)?;
    if rdata.remaining() != 0 || !is_mac_size_in_bounds(tsig.algorithm(), tsig.mac().len()) {
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

        labels.push(label.as_slice().to_vec());
    }

    if labels.is_empty() {
        return Ok(".".to_string());
    }

    Ok(format!("{}.", labels_to_presentation(&labels)))
}

#[cfg(test)]
pub(crate) mod tests;
