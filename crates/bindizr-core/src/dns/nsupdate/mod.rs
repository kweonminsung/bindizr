//! Decode, authenticate and answer DNS UPDATEs (RFC 2136); the service applies them.

pub mod parser;

use domain::base::Message;
use domain::base::iana::{Opcode, OptRcode};
use domain::rdata::tsig::Time48;

use crate::dns::message;
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
    let message = Message::from_octets(query_data)
        .map_err(|error| BuildResponseError::Malformed(Box::new(error)))?;
    let readable = message::has_readable_sections(query_data);

    for minimal in [false, true] {
        let rcode = if minimal { OptRcode::NOERROR } else { rcode };
        let mut builder = crate::dns::message::build_response();
        let mut answer = if readable {
            builder
                .start_answer(&message, rcode.rcode())
                .map_err(|error| BuildResponseError::Malformed(Box::new(error)))?
        } else {
            let header = builder.header_mut();
            header.set_id(message.header().id());
            header.set_qr(true);
            header.set_opcode(message.header().opcode());
            header.set_rd(message.header().rd());
            header.set_rcode(rcode.rcode());

            builder.answer()
        };
        answer.header_mut().set_tc(minimal);
        let mut additional = answer.additional();

        if readable {
            Edns::from_message(&message).push_response_opt(
                &mut additional,
                rcode,
                if minimal { None } else { ede },
                None,
            );
        }

        if let Some(signer) = signer.clone() {
            signer
                .sign_response_with_fudge(&mut additional, Time48::now(), fudge)
                .map_err(|error| EncodeMessageError::Sign(Box::new(error)))?;
        }

        let response = additional.finish().into_target();

        match limit.validate_len(response.len()) {
            Ok(()) => return Ok(response),
            Err(error) if minimal || !limit.is_udp() => return Err(error.into()),
            Err(_) => {}
        }
    }

    unreachable!()
}

#[cfg(test)]
mod tests;
