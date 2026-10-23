//! Validate a NOTIFY acknowledgement, including refusals without a question.

use domain::base::{
    Name,
    iana::{Opcode, OptRcode, Rtype},
};

use super::{ParseResponseError, parse_response, response_rcode, validate_question};

/// Check that a NOTIFY was acknowledged by the server we asked.
pub fn validate_notify_response(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<(), ParseResponseError> {
    let message = parse_response(query_id, Opcode::NOTIFY, response)
        .map_err(|error| ParseResponseError::Notify(Box::new(error)))?;

    // Read RCODE first: refusals may omit the question (NSD 4.6 NOTAUTH).
    let rcode = response_rcode(&message)?;

    if rcode != OptRcode::NOERROR {
        return Err(ParseResponseError::NotifyRcode(rcode));
    }

    // The acknowledgement copies the request's question (RFC 1996, Section 3.7).
    validate_question(&message, qname, Rtype::SOA)
        .map_err(|error| ParseResponseError::Notify(Box::new(error)))?;

    Ok(())
}
