//! Build outbound DNS questions and parse NOTIFY, SOA, DS, and transfer responses.

use domain::{
    base::{
        Message, MessageBuilder, Name, ToName,
        iana::{Class, Opcode, Rcode, Rtype},
        message_builder::AdditionalBuilder,
        rdata::ComposeRecordData,
    },
    rdata::{Ds, Soa},
};
use thiserror::Error;

use crate::dns::{
    LibraryError,
    dnssec::KeyTag,
    record::{EncodeRdataError, Rdata},
};

/// Why a DNS response could not be parsed or matched to its request.
#[derive(Debug, Error)]
pub enum ParseResponseError {
    #[error("malformed response: {0}")]
    Malformed(#[source] LibraryError),
    #[error("response ID mismatch: expected {expected}, got {got}")]
    IdMismatch { expected: u16, got: u16 },
    #[error("response does not have QR bit set")]
    NotResponse,
    #[error("response opcode mismatch: expected {expected}, got {got}")]
    OpcodeMismatch { expected: u8, got: u8 },
    #[error("truncated response")]
    Truncated,
    #[error("malformed question section: {0}")]
    MalformedQuestion(#[source] LibraryError),
    #[error("response answers another question")]
    OtherQuestion,
    #[error("response is not authoritative")]
    NotAuthoritative,
    #[error("RCODE {0}")]
    Rcode(u8),
    #[error("malformed answer section: {0}")]
    MalformedAnswer(#[source] LibraryError),
    #[error("malformed answer record: {0}")]
    MalformedAnswerRecord(#[source] LibraryError),
    #[error("transfer carries a class {class} record for {owner}")]
    ForeignClass { class: Class, owner: String },
    #[error(transparent)]
    Rdata(#[from] EncodeRdataError),
    /// The NOTIFY acknowledgement did not read as one; the source says why.
    #[error("NOTIFY {0}")]
    Notify(#[source] Box<ParseResponseError>),
    #[error("NOTIFY response opcode mismatch: expected {}, got {got}", Opcode::NOTIFY.to_int())]
    NotifyOpcode { got: u8 },
    #[error("NOTIFY response returned RCODE {0}")]
    NotifyRcode(u8),
    #[error("no SOA record in answer")]
    NoSoa,
    #[error("malformed authority section: {0}")]
    MalformedAuthority(#[source] LibraryError),
    #[error("malformed authority record: {0}")]
    MalformedAuthorityRecord(#[source] LibraryError),
    #[error("negative answer carries no SOA of a parent zone")]
    NoParentSoa,
}

/// EDNS0 payload size advertised where the answer may outgrow 512 bytes (a
/// TLD's NS record set): the DNS flag day 2020 value.
pub const EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

/// Build a question with a random ID and optional EDNS, leaving the
/// additional section open for signing before the caller finishes it.
pub fn build_question(
    opcode: Opcode,
    aa: bool,
    rd: bool,
    qname: &Name<Vec<u8>>,
    rtype: Rtype,
    edns_udp_payload_size: Option<u16>,
) -> (u16, AdditionalBuilder<Vec<u8>>) {
    let query_id = rand::random::<u16>();

    let mut builder = MessageBuilder::new_vec();
    let header = builder.header_mut();
    header.set_id(query_id);
    header.set_opcode(opcode);
    header.set_aa(aa);
    header.set_rd(rd);

    let mut question = builder.question();
    question
        .push((qname, rtype))
        .expect("one question fits an unlimited message");

    let mut additional = question.additional();
    if let Some(udp_payload_size) = edns_udp_payload_size {
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(udp_payload_size);
                Ok(())
            })
            .expect("one OPT record fits an unlimited message");
    }

    (query_id, additional)
}

/// Whether a response carries the TC flag: the answer did not fit the UDP
/// payload and is to be asked again over TCP (RFC 1035, Section 4.2.1).
pub fn is_truncated(response: &[u8]) -> bool {
    Message::from_octets(response).is_ok_and(|message| message.header().tc())
}

/// Match and structurally validate an incoming datagram before trusting its flags
/// (RFC 1035, Section 7.3; RFC 5452, Section 9.1).
pub fn matches_response_to_request(request: &[u8], response: &[u8]) -> bool {
    use domain::rdata::AllRecordData;

    let (Ok(request), Ok(response)) = (
        Message::from_octets(request),
        Message::from_octets(response),
    ) else {
        return false;
    };
    if !response.header().qr()
        || response.header().id() != request.header().id()
        || response.header().opcode() != request.header().opcode()
    {
        return false;
    }
    // Some NOTIFY refusals omit the question; retain the server's error.
    let empty_notify_error = response.header().opcode() == Opcode::NOTIFY
        && response.header().rcode() != Rcode::NOERROR
        && response.header_counts().qdcount() == 0;
    if !empty_notify_error {
        let (Ok(wanted), Ok(answered)) = (request.sole_question(), response.sole_question()) else {
            return false;
        };
        if !wanted.qname().name_eq(answered.qname())
            || wanted.qtype() != answered.qtype()
            || wanted.qclass() != answered.qclass()
        {
            return false;
        }
    }
    for section in [
        response.answer(),
        response.authority(),
        response.additional(),
    ] {
        let Ok(section) = section else {
            return false;
        };
        if section
            .limit_to::<AllRecordData<_, _>>()
            .any(|record| record.is_err())
        {
            return false;
        }
    }
    true
}

/// `parse_response`, plus the echoed question must be ours (`qname`, `rtype`,
/// class IN).
fn parse_question_response<'a>(
    query_id: u16,
    opcode: Opcode,
    qname: &Name<Vec<u8>>,
    rtype: Rtype,
    response: &'a [u8],
) -> Result<Message<&'a [u8]>, ParseResponseError> {
    let message = parse_response(query_id, opcode, response)?;
    let question = message
        .sole_question()
        .map_err(|e| ParseResponseError::MalformedQuestion(Box::new(e)))?;
    if !question.qname().name_eq(qname)
        || question.qtype() != rtype
        || question.qclass() != Class::IN
    {
        return Err(ParseResponseError::OtherQuestion);
    }
    Ok(message)
}

/// Parse a matching question response and require the authoritative (AA) flag.
fn parse_authoritative_response<'a>(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    rtype: Rtype,
    response: &'a [u8],
) -> Result<Message<&'a [u8]>, ParseResponseError> {
    let message = parse_question_response(query_id, Opcode::QUERY, qname, rtype, response)?;
    if !message.header().aa() {
        return Err(ParseResponseError::NotAuthoritative);
    }
    Ok(message)
}

/// Check a response answers our question: our id, QR set, not truncated.
/// The RCODE is the caller's, since NXDOMAIN answers some questions.
fn parse_response(
    query_id: u16,
    opcode: Opcode,
    response: &[u8],
) -> Result<Message<&[u8]>, ParseResponseError> {
    let message =
        Message::from_octets(response).map_err(|e| ParseResponseError::Malformed(Box::new(e)))?;

    let header = message.header();
    if header.id() != query_id {
        return Err(ParseResponseError::IdMismatch {
            expected: query_id,
            got: header.id(),
        });
    }
    if header.opcode() != opcode {
        return Err(ParseResponseError::OpcodeMismatch {
            expected: opcode.to_int(),
            got: header.opcode().to_int(),
        });
    }
    if !header.qr() {
        return Err(ParseResponseError::NotResponse);
    }
    if header.tc() {
        return Err(ParseResponseError::Truncated);
    }
    Ok(message)
}

/// One answer record with uncompressed, canonical RDATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRecord {
    /// Owner name as an absolute presentation name (trailing dot).
    pub name: String,
    pub rtype: Rtype,
    pub ttl: u32,
    pub rdata: Rdata,
}

/// Validate one AXFR response message and collect every answer record; the
/// caller assembles the stream (SOA-delimited per RFC 5936, Section 2.2).
/// The first message must echo the question and be authoritative; later
/// ones may omit the question (RFC 5936, Sections 2.2.1 and 2.2.2).
pub fn extract_transfer_records(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    position: TransferMessagePosition,
    response: &[u8],
) -> Result<Vec<TransferRecord>, ParseResponseError> {
    use domain::rdata::AllRecordData;

    let message = if position == TransferMessagePosition::First {
        parse_authoritative_response(query_id, qname, Rtype::AXFR, response)?
    } else if parse_response(query_id, Opcode::QUERY, response)?
        .header_counts()
        .qdcount()
        == 1
    {
        parse_question_response(query_id, Opcode::QUERY, qname, Rtype::AXFR, response)?
    } else {
        parse_response(query_id, Opcode::QUERY, response)?
    };
    if message.header().rcode() != Rcode::NOERROR {
        return Err(ParseResponseError::Rcode(message.header().rcode().to_int()));
    }

    let answer = message
        .answer()
        .map_err(|e| ParseResponseError::MalformedAnswer(Box::new(e)))?;
    let mut records = Vec::new();
    for record in answer.limit_to::<AllRecordData<_, _>>() {
        let record = record.map_err(|e| ParseResponseError::MalformedAnswerRecord(Box::new(e)))?;
        // A zone transfer is single-class; rendering would rewrite any other
        // class as IN.
        if record.class() != Class::IN {
            return Err(ParseResponseError::ForeignClass {
                class: record.class(),
                owner: record.owner().to_string(),
            });
        }
        let mut rdata = Vec::new();
        let Ok(()) = record.data().compose_rdata(&mut rdata);
        records.push(TransferRecord {
            // Display omits the root dot; the absolute form keeps the
            // import parser from re-qualifying the name.
            name: format!("{}.", record.owner()),
            rtype: record.rtype(),
            ttl: record.ttl().as_secs(),
            rdata: Rdata::new(rdata)?,
        });
    }
    Ok(records)
}

/// Check that a NOTIFY was acknowledged by the server we asked.
pub fn validate_notify_response(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<(), ParseResponseError> {
    let message = parse_response(query_id, Opcode::NOTIFY, response)
        .map_err(|e| ParseResponseError::Notify(Box::new(e)))?;
    let header = message.header();
    if header.opcode() != Opcode::NOTIFY {
        return Err(ParseResponseError::NotifyOpcode {
            got: header.opcode().to_int(),
        });
    }
    // A refusal may omit the question (NSD 4.6's NOTAUTH does), so its RCODE
    // is read first.
    if header.rcode() != Rcode::NOERROR {
        return Err(ParseResponseError::NotifyRcode(header.rcode().to_int()));
    }
    // The acknowledgement copies the request's question (RFC 1996, Section 3.7).
    parse_question_response(query_id, Opcode::NOTIFY, qname, Rtype::SOA, response)
        .map_err(|e| ParseResponseError::Notify(Box::new(e)))?;
    Ok(())
}

/// Read an authoritative SOA answer's serial: the serial a secondary itself
/// serves for `qname`, which a cache's answer would not be.
pub fn extract_soa_serial(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<u32, ParseResponseError> {
    let message = parse_authoritative_response(query_id, qname, Rtype::SOA, response)?;
    if message.header().rcode() != Rcode::NOERROR {
        return Err(ParseResponseError::Rcode(message.header().rcode().to_int()));
    }

    let answer = message
        .answer()
        .map_err(|e| ParseResponseError::MalformedAnswer(Box::new(e)))?;
    answer
        .limit_to::<Soa<_>>()
        .filter_map(|record| record.ok())
        .find(|record| record.owner().name_eq(qname))
        .map(|record| record.data().serial().into_int())
        .ok_or(ParseResponseError::NoSoa)
}

/// The DS record set a parent-zone server holds for a child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRecordSet {
    /// The DS records at the child's name, ordered by key tag then RDATA and
    /// deduplicated.
    pub records: Vec<DsRecord>,
    /// The record set's TTL: how long a cache may keep serving these DS records.
    pub ttl: u32,
}

impl DsRecordSet {
    /// Key tags of the keys the records name, ascending and deduplicated.
    pub fn key_tags(&self) -> Vec<KeyTag> {
        let mut key_tags: Vec<KeyTag> = self.records.iter().map(|record| record.key_tag).collect();
        key_tags.dedup();
        key_tags
    }
}

/// One DS record of a parent's answer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DsRecord {
    pub key_tag: KeyTag,
    pub digest_type: u8,
    /// The RDATA of RFC 4034, Section 5.1; matched whole, since keys can
    /// share a 16-bit tag.
    pub rdata: Vec<u8>,
}

/// Read an authoritative DS answer, or `None` for NODATA/NXDOMAIN.
/// Reject non-authoritative answers because cached parent data may be stale.
pub fn extract_ds_record_set(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<Option<DsRecordSet>, ParseResponseError> {
    let message = parse_authoritative_response(query_id, qname, Rtype::DS, response)?;
    match message.header().rcode() {
        Rcode::NOERROR => {}
        Rcode::NXDOMAIN => return validate_parent_soa(&message, qname).map(|_| None),
        rcode => return Err(ParseResponseError::Rcode(rcode.to_int())),
    }

    let answer = message
        .answer()
        .map_err(|e| ParseResponseError::MalformedAnswer(Box::new(e)))?;
    let mut records = Vec::new();
    let mut ttl: Option<u32> = None;
    for record in answer.limit_to::<Ds<_>>() {
        let record = record.map_err(|e| ParseResponseError::MalformedAnswerRecord(Box::new(e)))?;
        // Only DS records at the child's own name are its delegation.
        if !record.owner().name_eq(qname) {
            continue;
        }
        let mut rdata = Vec::new();
        let Ok(()) = record.data().compose_rdata(&mut rdata);
        records.push(DsRecord {
            key_tag: KeyTag::from(record.data().key_tag()),
            digest_type: record.data().digest_type().to_int(),
            rdata,
        });
        ttl = Some(ttl.map_or(record.ttl().as_secs(), |t| t.min(record.ttl().as_secs())));
    }
    let Some(ttl) = ttl else {
        return validate_parent_soa(&message, qname).map(|_| None);
    };
    records.sort();
    records.dedup();
    Ok(Some(DsRecordSet { records, ttl }))
}

/// Require a strict ancestor's SOA for negative DS answers (RFC 2308, Section 2);
/// the child's own authoritative NODATA does not prove the parent has no DS.
fn validate_parent_soa(
    message: &Message<&[u8]>,
    qname: &Name<Vec<u8>>,
) -> Result<(), ParseResponseError> {
    let authority = message
        .authority()
        .map_err(|e| ParseResponseError::MalformedAuthority(Box::new(e)))?;
    for record in authority.limit_to::<Soa<_>>() {
        let record =
            record.map_err(|e| ParseResponseError::MalformedAuthorityRecord(Box::new(e)))?;
        if qname.ends_with(record.owner()) && !qname.name_eq(record.owner()) {
            return Ok(());
        }
    }
    Err(ParseResponseError::NoParentSoa)
}

#[cfg(test)]
mod tests;

/// A transfer message's position determines which header checks apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMessagePosition {
    First,
    Following,
}
