//! Decode, authenticate and answer DNS UPDATEs (RFC 2136); the service applies them.

pub mod parser;

use domain::{
    base::{
        Message,
        iana::{Opcode, OptRcode},
    },
    rdata::tsig::Time48,
};

use crate::dns::message::{Edns, EncodeMessageError, ExtendedErrorCode, ResponseLimit};

/// Response-TSIG fudge for requests whose own fudge is unavailable
/// (RFC 8945, Section 10 suggested default).
pub const DEFAULT_FUDGE: u16 = 300;

/// Check whether a DNS message uses the UPDATE opcode.
pub fn is_nsupdate(message: &[u8]) -> bool {
    Message::from_octets(message).is_ok_and(|message| message.header().opcode() == Opcode::UPDATE)
}

/// Why an UPDATE response could not be encoded.
#[derive(Debug, thiserror::Error)]
pub enum BuildResponseError {
    #[error("invalid UPDATE message: {0}")]
    Malformed(#[source] crate::dns::LibraryError),
    #[error(transparent)]
    Encode(#[from] EncodeMessageError),
}

/// Build an UPDATE response with request OPT (RFC 6891, Section 6.1.1) and validated TSIG (RFC 8945, Section 5.3).
/// Echo only the zone section, a BIND-compatible exception to RFC 2136, Section 3.8.
pub fn build_response(
    query_data: &[u8],
    rcode: OptRcode,
    ede: Option<ExtendedErrorCode>,
    signer: Option<crate::dns::tsig::ResponseSigner>,
    fudge: u16,
    limit: ResponseLimit,
) -> Result<Vec<u8>, BuildResponseError> {
    let msg =
        Message::from_octets(query_data).map_err(|e| BuildResponseError::Malformed(Box::new(e)))?;
    for minimal in [false, true] {
        let rcode = if minimal { OptRcode::NOERROR } else { rcode };
        let mut answer = crate::dns::message::build_response()
            .start_answer(&msg, rcode.rcode())
            .map_err(|e| BuildResponseError::Malformed(Box::new(e)))?;
        answer.header_mut().set_tc(minimal);
        let mut additional = answer.additional();
        Edns::from_message(&msg).push_response(
            &mut additional,
            rcode,
            if minimal { None } else { ede },
            None,
        );
        if let Some(signer) = signer.clone() {
            signer
                .sign_response_with_fudge(&mut additional, Time48::now(), fudge)
                .map_err(|e| EncodeMessageError::Sign(Box::new(e)))?;
        }
        let response = additional.finish().into_target();
        match limit.check_len(response.len()) {
            Ok(()) => return Ok(response),
            Err(error) if minimal || !limit.is_udp() => return Err(error.into()),
            Err(_) => {}
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests;
