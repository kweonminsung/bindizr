//! Shared DNS response identity checks and protocol-specific response decoders.

mod ds;
mod keepalive;
mod notify;
mod soa;
mod transfer;

use domain::base::{
    Message, Name, ToName,
    iana::{Class, Opcode, OptRcode, Rtype},
};
pub use ds::{DsRecord, DsRecordSet, extract_ds_record_set};
pub use keepalive::extract_tcp_keepalive_timeout;
pub use notify::validate_notify_response;
pub use soa::extract_soa_serial;
use thiserror::Error;
pub use transfer::{TransferMessagePosition, TransferRecord, extract_transfer_records};

use crate::dns::{LibraryError, message::Edns, record::EncodeRdataError};

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
    #[error("RCODE {}", .0.to_int())]
    Rcode(OptRcode),
    #[error("malformed response OPT record")]
    MalformedEdns,
    #[error("malformed answer section: {0}")]
    MalformedAnswer(#[source] LibraryError),
    #[error("malformed answer record: {0}")]
    MalformedAnswerRecord(#[source] LibraryError),
    #[error("response carries a class {class} record for {owner}")]
    ForeignClass { class: Class, owner: String },
    #[error(transparent)]
    Rdata(#[from] EncodeRdataError),
    /// The NOTIFY acknowledgement did not read as one; the source says why.
    #[error("NOTIFY {0}")]
    Notify(#[source] Box<ParseResponseError>),
    #[error("NOTIFY response returned RCODE {}", .0.to_int())]
    NotifyRcode(OptRcode),
    #[error("no SOA record in answer")]
    NoSoa,
    #[error("malformed authority section: {0}")]
    MalformedAuthority(#[source] LibraryError),
    #[error("malformed authority record: {0}")]
    MalformedAuthorityRecord(#[source] LibraryError),
    #[error("negative answer carries no SOA of a parent zone")]
    NoParentSoa,
}

/// Read TC to decide whether UDP needs a TCP retry (RFC 1035, Section 4.2.1).
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

    let Ok(rcode) = response_rcode(&response) else {
        return false;
    };

    // Some NOTIFY refusals omit the question; retain the server's error.
    let empty_notify_error = response.header().opcode() == Opcode::NOTIFY
        && rcode != OptRcode::NOERROR
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

    // A matching header is insufficient when a record section is malformed.
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

/// Parse a response with the expected IN question.
fn parse_question_response<'a>(
    query_id: u16,
    opcode: Opcode,
    qname: &Name<Vec<u8>>,
    rtype: Rtype,
    response: &'a [u8],
) -> Result<Message<&'a [u8]>, ParseResponseError> {
    let message = parse_response(query_id, opcode, response)?;
    validate_question(&message, qname, rtype)?;
    Ok(message)
}

/// Require exactly the IN question that was sent.
fn validate_question(
    message: &Message<&[u8]>,
    qname: &Name<Vec<u8>>,
    rtype: Rtype,
) -> Result<(), ParseResponseError> {
    let question = message
        .sole_question()
        .map_err(|error| ParseResponseError::MalformedQuestion(Box::new(error)))?;

    if !question.qname().name_eq(qname)
        || question.qtype() != rtype
        || question.qclass() != Class::IN
    {
        return Err(ParseResponseError::OtherQuestion);
    }

    Ok(())
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

/// Check ID, QR, and TC; leave RCODE policy to the caller.
fn parse_response(
    query_id: u16,
    opcode: Opcode,
    response: &[u8],
) -> Result<Message<&[u8]>, ParseResponseError> {
    let message = parse_response_header(query_id, opcode, response)?;
    if message.header().tc() {
        return Err(ParseResponseError::Truncated);
    }
    Ok(message)
}

/// Validate response identity and direction, leaving flag policy to the caller.
fn parse_response_header(
    query_id: u16,
    opcode: Opcode,
    response: &[u8],
) -> Result<Message<&[u8]>, ParseResponseError> {
    let message = Message::from_octets(response)
        .map_err(|error| ParseResponseError::Malformed(Box::new(error)))?;

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

    Ok(message)
}

/// Read all twelve RCODE bits after checking OPT placement and structure.
fn response_rcode(message: &Message<&[u8]>) -> Result<OptRcode, ParseResponseError> {
    if Edns::from_message(message) == Edns::Malformed {
        return Err(ParseResponseError::MalformedEdns);
    }
    // RFC 6891, Section 6.1.3: response VERSION advertises capability, so allow newer versions.
    Ok(message.opt_rcode())
}
