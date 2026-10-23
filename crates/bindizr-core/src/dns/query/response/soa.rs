//! Decode the authoritative SOA serial answering a probe.

use domain::{
    base::{
        Name, ToName,
        iana::{Class, OptRcode, Rtype},
    },
    rdata::Soa,
};

use super::{ParseResponseError, parse_authoritative_response, response_rcode};

/// Read the serial served authoritatively for `qname`.
pub fn extract_soa_serial(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<u32, ParseResponseError> {
    let message = parse_authoritative_response(query_id, qname, Rtype::SOA, response)?;
    let rcode = response_rcode(&message)?;

    if rcode != OptRcode::NOERROR {
        return Err(ParseResponseError::Rcode(rcode));
    }

    let answer = message
        .answer()
        .map_err(|error| ParseResponseError::MalformedAnswer(Box::new(error)))?;

    for record in answer.limit_to::<Soa<_>>() {
        let record =
            record.map_err(|error| ParseResponseError::MalformedAnswerRecord(Box::new(error)))?;

        if record.owner().name_eq(qname) {
            if record.class() != Class::IN {
                return Err(ParseResponseError::ForeignClass {
                    class: record.class(),
                    owner: record.owner().to_string(),
                });
            }

            return Ok(record.data().serial().into_int());
        }
    }

    Err(ParseResponseError::NoSoa)
}
