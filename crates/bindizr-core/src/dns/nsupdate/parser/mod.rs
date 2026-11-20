mod record;

use domain::base::Message;
use domain::base::iana::{Class, Opcode, Rtype};
use domain::base::name::ParsedName;
use domain::dep::octseq::parse::Parser;
pub use record::{UpdateRecord, ValidateUpdateShapeError};
use thiserror::Error;

use crate::dns::message::{DNS_HEADER_LEN, Edns};
use crate::dns::record::{ParseRdataError, ParseRecordValueError};
use crate::dns::tsig::{RequestSignature, RequestTsig};
use crate::dns::{name, tsig};
use crate::model::record::ParseRecordTypeError;

/// Why an UPDATE message could not be parsed into its sections.
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
    Rdata { record_type: &'static str },
    #[error("invalid rdata: {0}")]
    ParseRdata(#[from] ParseRdataError),
    #[error(transparent)]
    RecordType(#[from] ParseRecordTypeError),
    #[error(transparent)]
    Value(#[from] ParseRecordValueError),
}

/// A parsed UPDATE message: its zone, prerequisites, updates, TSIG, and OPT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    pub zone_name: String,
    pub zone_class: Class,
    pub prerequisites: Vec<UpdateRecord>,
    pub updates: Vec<UpdateRecord>,
    pub tsig: Option<RequestTsig>,
    pub edns: Edns,
}

impl UpdateRequest {
    /// Parse the zone, prerequisites, updates, and TSIG from an UPDATE message.
    pub fn parse(query_data: &[u8]) -> Result<Self, ParseUpdateError> {
        let message = Message::from_octets(query_data).map_err(|_| ParseUpdateError::TooShort)?;

        if message.header().opcode() != Opcode::UPDATE {
            return Err(ParseUpdateError::InvalidOpcode);
        }

        let counts = message.header_counts();

        if counts.qdcount() != 1 {
            return Err(ParseUpdateError::InvalidHeader);
        }

        let mut parser = Parser::from_ref(query_data);
        parser
            .advance(DNS_HEADER_LEN)
            .map_err(|_| ParseUpdateError::TooShort)?;

        // RFC 2136, Section 3.1.1 requires SOA; authority over ZCLASS is
        // decided by the service, not by the wire parser.
        let zname = ParsedName::parse(&mut parser).map_err(|_| ParseUpdateError::InvalidName)?;
        let ztype = parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidZoneSection)?;
        let zclass = parser
            .parse_u16_be()
            .map_err(|_| ParseUpdateError::InvalidZoneSection)?;

        if Rtype::from_int(ztype) != Rtype::SOA {
            return Err(ParseUpdateError::InvalidZoneSection);
        }

        let zone_name = to_presentation_name(&zname);

        // UPDATE uses the answer count for prerequisites and the authority count
        // for changes; these are not ordinary response sections.
        let mut prerequisites = Vec::with_capacity(usize::from(counts.ancount()));

        for _ in 0..counts.ancount() {
            prerequisites.push(parse_record(&mut parser, query_data)?);
        }

        let mut updates = Vec::with_capacity(usize::from(counts.nscount()));

        for _ in 0..counts.nscount() {
            updates.push(parse_record(&mut parser, query_data)?);
        }

        skip_additional_section(&mut parser, usize::from(counts.arcount()))?;

        if parser.remaining() != 0 {
            return Err(ParseUpdateError::InvalidHeader);
        }

        // RFC 8945, Section 5.2: a misplaced or malformed TSIG is FORMERR,
        // never an unsigned request; the tsig module reads its placement.
        let tsig = match tsig::request_signature(query_data) {
            RequestSignature::Absent => None,
            RequestSignature::Malformed => return Err(ParseUpdateError::InvalidTsig),
            RequestSignature::Key(tsig) => Some(tsig),
        };

        Ok(Self {
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
    query_data: &[u8],
) -> Result<UpdateRecord, ParseUpdateError> {
    let name = ParsedName::parse(parser).map_err(|_| ParseUpdateError::InvalidName)?;
    let name = to_presentation_name(&name);

    let rtype = Rtype::from_int(
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
        record_type: rtype,
        class,
        ttl,
        rdata: query_data[rdata_start..rdata_start + rdlen].to_vec(),
        rdata_start,
    })
}

/// Step over the Additional records; OPT and TSIG are read by their own decoders.
fn skip_additional_section(
    parser: &mut Parser<'_, [u8]>,
    count: usize,
) -> Result<(), ParseUpdateError> {
    for _ in 0..count {
        ParsedName::parse(parser).map_err(|_| ParseUpdateError::InvalidName)?;
        // TYPE, CLASS and TTL are opaque here.
        parser
            .advance(8)
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

    Ok(())
}

/// Render a parsed name in presentation form, escaping a `.` or `\` inside a
/// label so the text decodes back to the same labels (RFC 1035, Section 5.1).
fn to_presentation_name(name: &ParsedName<&[u8]>) -> String {
    let mut labels = Vec::new();

    for label in name {
        if label.is_root() {
            break;
        }

        labels.push(label.as_slice().to_vec());
    }

    if labels.is_empty() {
        return ".".to_string();
    }

    format!("{}.", name::labels_to_presentation(&labels))
}

#[cfg(test)]
pub(crate) mod tests;
