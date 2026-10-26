//! Compose TSIG failures separately from request authentication.
use domain::base::Message;
use domain::base::iana::{Class, OptRcode, Rcode, TsigRcode};
use domain::base::message_builder::{AdditionalBuilder, TreeCompressor};
use domain::rdata::tsig::{Time48, Tsig};
use ring::hmac;

use super::{TsigError, TsigSigningKey};
use crate::dns::message::{Edns, ResponseLimit};

/// Build the signed or unsigned validation error required by RFC 8945, Section 5.3.2.
pub fn build_error_response(
    query_data: &[u8],
    key: Option<&TsigSigningKey>,
    error: TsigRcode,
    now: Time48,
    limit: ResponseLimit,
) -> Result<Vec<u8>, TsigError> {
    let message =
        Message::from_octets(query_data).map_err(|error| TsigError::Malformed(Box::new(error)))?;

    for include_question in [true, false] {
        // Keep stream questions (RFC 5936, Section 2.2.2); only oversized UDP errors omit them.
        // Re-sign without changing BADTIME's error or client time (RFC 8945, Section 5.2.3).
        if !include_question && !limit.is_udp() {
            break;
        }

        let response = match (error, key) {
            (TsigRcode::BADTIME, Some(key)) => build_signed_error_response(
                &message,
                key,
                AuthenticatedError::BadTime,
                now,
                include_question,
            ),
            (TsigRcode::BADTRUNC, Some(key)) => build_signed_error_response(
                &message,
                key,
                AuthenticatedError::BadTrunc,
                now,
                include_question,
            ),
            _ => build_unsigned_error_response(&message, error, include_question),
        };

        if let Some(response) = response
            && limit.validate_len(response.len()).is_ok()
        {
            return Ok(response);
        }
    }

    Err(TsigError::BuildResponse { rcode: error })
}

/// Echo the question when it fits; a compact UDP error retains the request header.
fn start_error_response(
    message: &Message<&[u8]>,
    include_question: bool,
) -> Option<AdditionalBuilder<TreeCompressor<Vec<u8>>>> {
    let mut builder = crate::dns::message::build_response();

    if include_question {
        return Some(
            builder
                .start_answer(message, Rcode::NOTAUTH)
                .ok()?
                .additional(),
        );
    }

    let header = builder.header_mut();
    header.set_id(message.header().id());
    header.set_opcode(message.header().opcode());
    header.set_rd(message.header().rd());
    header.set_qr(true);
    header.set_rcode(Rcode::NOTAUTH);

    Some(builder.additional())
}

/// TSIG failures that follow successful MAC validation.
#[derive(Clone, Copy)]
enum AuthenticatedError {
    BadTime,
    BadTrunc,
}

/// Sign a time or truncation error, including EDNS (RFC 8945, Section 5.3.2).
fn build_signed_error_response(
    message: &Message<&[u8]>,
    key: &TsigSigningKey,
    error: AuthenticatedError,
    now: Time48,
    include_question: bool,
) -> Option<Vec<u8>> {
    use domain::base::ToName;

    let request_tsig = message
        .additional()
        .ok()?
        .limit_to::<Tsig<_, _>>()
        .last()?
        .ok()?;
    let request = request_tsig.data();
    let mut builder = start_error_response(message, include_question)?;
    Edns::from_message(message).push_response_opt(&mut builder, OptRcode::NOTAUTH, None, None);

    // domain 0.12.3 omits OPT and hashes eight Other Data bytes; RFC 8945,
    // Section 4.3 requires the six carried on the wire.
    let name = key.domain.name().to_canonical_name::<Vec<u8>>();
    let algorithm = key.domain.algorithm().to_name();
    let (rcode, time_signed, other) = match error {
        AuthenticatedError::BadTime => (
            TsigRcode::BADTIME,
            request.time_signed(),
            Some(now.into_octets()),
        ),
        AuthenticatedError::BadTrunc => (TsigRcode::BADTRUNC, now, None),
    };
    let other = other.as_ref().map_or(&[][..], |time| time.as_slice());

    // The request MAC binds this signed error to the request that caused it.
    let mut digest = hmac::Context::with_key(&key.hmac);
    digest.update(&u16::try_from(request.mac().len()).ok()?.to_be_bytes());
    digest.update(request.mac());
    digest.update(builder.as_slice());
    digest.update(name.as_slice());
    digest.update(&Class::ANY.to_int().to_be_bytes());
    digest.update(&0u32.to_be_bytes());
    digest.update(algorithm.as_slice());
    digest.update(&time_signed.into_octets());
    digest.update(&request.fudge().to_be_bytes());
    digest.update(&rcode.to_int().to_be_bytes());
    digest.update(&u16::try_from(other.len()).ok()?.to_be_bytes());
    digest.update(other);
    let mac = digest.sign();
    builder
        .push((
            key.domain.name(),
            Class::ANY,
            0,
            Tsig::new(
                algorithm,
                time_signed,
                request.fudge(),
                mac.as_ref(),
                message.header().id(),
                rcode,
                other,
            )
            .ok()?,
        ))
        .ok()?;

    Some(builder.finish().into_target())
}

/// Build NOTAUTH with an echoed, unsigned TSIG and empty MAC (RFC 8945, Section 5.3.2).
fn build_unsigned_error_response(
    message: &Message<&[u8]>,
    error: TsigRcode,
    include_question: bool,
) -> Option<Vec<u8>> {
    let tsig_record = message
        .additional()
        .ok()?
        .limit_to::<Tsig<_, _>>()
        .last()?
        .ok()?;

    let mut builder = start_error_response(message, include_question)?;
    Edns::from_message(message).push_response_opt(&mut builder, OptRcode::NOTAUTH, None, None);
    builder
        .push((
            tsig_record.owner(),
            tsig_record.class(),
            tsig_record.ttl(),
            Tsig::new(
                tsig_record.data().algorithm(),
                tsig_record.data().time_signed(),
                tsig_record.data().fudge(),
                b"",
                message.header().id(),
                error,
                b"",
            )
            .ok()?,
        ))
        .ok()?;

    Some(builder.finish().into_target())
}
