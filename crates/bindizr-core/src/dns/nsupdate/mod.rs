//! RFC 2136 dynamic update on the wire: decoding an UPDATE message, TSIG
//! authentication, and building the response. Applying the changes is the
//! service layer's.

pub mod auth;
pub mod parser;
#[cfg(test)]
mod tests;

use domain::{
    base::{
        Message, MessageBuilder,
        iana::{Opcode, Rcode},
    },
    rdata::tsig::Time48,
};

/// Response-TSIG fudge for requests whose own fudge is unavailable
/// (RFC 8945, Section 10 suggested default).
pub const DEFAULT_FUDGE: u16 = 300;

pub fn is_nsupdate(message: &[u8]) -> bool {
    Message::from_octets(message).is_ok_and(|message| message.header().opcode() == Opcode::UPDATE)
}

/// Build the response: request ID/opcode/question echoed, RCODE set, and a
/// TSIG appended once the request's TSIG was validated — every response to a
/// signed request must be signed (RFC 8945, Section 5.3).
pub fn build_response(
    query_data: &[u8],
    rcode: Rcode,
    signer: Option<auth::ResponseSigner>,
    fudge: u16,
) -> Option<Vec<u8>> {
    let msg = Message::from_octets(query_data).ok()?;
    let answer = MessageBuilder::new_vec().start_answer(&msg, rcode).ok()?;
    let mut additional = answer.additional();

    if let Some(signer) = signer {
        signer
            .answer_with_fudge(&mut additional, Time48::now(), fudge)
            .ok()?;
    }

    Some(additional.finish())
}
