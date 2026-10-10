//! nsupdate (RFC 2136) on the wire: decoding an UPDATE message, TSIG
//! authentication, and building the response. Applying the changes is the
//! service layer's.

pub mod parser;

use domain::{
    base::{
        Message, MessageBuilder,
        iana::{Opcode, OptRcode},
    },
    rdata::tsig::Time48,
};

use crate::dns::message::{Edns, ExtendedErrorCode};

/// Response-TSIG fudge for requests whose own fudge is unavailable
/// (RFC 8945, Section 10 suggested default).
pub const DEFAULT_FUDGE: u16 = 300;

/// Check whether a DNS message uses the UPDATE opcode.
pub fn is_nsupdate(message: &[u8]) -> bool {
    Message::from_octets(message).is_ok_and(|message| message.header().opcode() == Opcode::UPDATE)
}

/// Build the response: request ID/opcode/question echoed, RCODE set, an OPT
/// when the request carried one (RFC 6891, Section 6.1.1), and a TSIG once
/// the request's was validated (RFC 8945, Section 5.3).
pub fn build_response(
    query_data: &[u8],
    rcode: OptRcode,
    ede: Option<ExtendedErrorCode>,
    signer: Option<crate::dns::tsig::ResponseSigner>,
    fudge: u16,
) -> Option<Vec<u8>> {
    let msg = Message::from_octets(query_data).ok()?;
    let answer = MessageBuilder::new_vec()
        .start_answer(&msg, rcode.rcode())
        .ok()?;
    let mut additional = answer.additional();
    Edns::from_message(&msg).push_response(&mut additional, rcode, ede, None);

    if let Some(signer) = signer {
        signer
            .answer_with_fudge(&mut additional, Time48::now(), fudge)
            .ok()?;
    }

    Some(additional.finish())
}

#[cfg(test)]
mod tests;
