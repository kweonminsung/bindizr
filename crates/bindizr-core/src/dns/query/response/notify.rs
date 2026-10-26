//! Validate a NOTIFY acknowledgement, including refusals without a question.

use domain::base::Name;
use domain::base::iana::{Opcode, OptRcode, Rtype};

use super::ParseResponseError;

/// Check that a NOTIFY was acknowledged by the server we asked.
pub fn validate_notify_response(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<(), ParseResponseError> {
    let message = super::parse_response(query_id, Opcode::NOTIFY, response)
        .map_err(|error| ParseResponseError::Notify(Box::new(error)))?;

    // Read RCODE first: refusals may omit the question (NSD 4.6 NOTAUTH).
    let rcode = super::response_rcode(&message)?;

    if rcode != OptRcode::NOERROR {
        return Err(ParseResponseError::NotifyRcode(rcode));
    }

    // The acknowledgement copies the request's question (RFC 1996, Section 3.7).
    super::validate_question(&message, qname, Rtype::SOA)
        .map_err(|error| ParseResponseError::Notify(Box::new(error)))?;

    Ok(())
}
