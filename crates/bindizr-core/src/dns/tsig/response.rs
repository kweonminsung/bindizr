//! Compose TSIG failures separately from request authentication.

use domain::base::Message;
use domain::base::iana::{Class, OptRcode, Rcode, TsigRcode};
use domain::base::message_builder::{AdditionalBuilder, TreeCompressor};
use domain::rdata::tsig::{Time48, Tsig};
use ring::hmac;

use crate::dns::message::{Edns, ResponseLimit};
use crate::dns::tsig::{TsigError, TsigSigningKey};
use crate::dns::{LibraryError, message, tsig};

/// Build the signed or unsigned validation error required by RFC 8945, Section 5.3.2.
pub fn build_error_response(
    query_data: &[u8],
    key: Option<&TsigSigningKey>,
    rcode: TsigRcode,
    now: Time48,
    limit: ResponseLimit,
) -> Result<Vec<u8>, TsigError> {
    let message =
        Message::from_octets(query_data).map_err(|error| TsigError::Malformed(Box::new(error)))?;

    let build = |include_question| -> Result<Vec<u8>, LibraryError> {
        let response = match (rcode, key) {
            (TsigRcode::BADTIME, Some(key)) => build_signed_error_response(
                &message,
                key,
                AuthenticatedError::BadTime,
                now,
                include_question,
            )?,
            (TsigRcode::BADTRUNC, Some(key)) => build_signed_error_response(
                &message,
                key,
                AuthenticatedError::BadTrunc,
                now,
                include_question,
            )?,
            _ => build_unsigned_error_response(&message, rcode, include_question)?,
        };
        limit.validate_len(response.len())?;
        Ok(response)
    };

    // Keep stream questions (RFC 5936, Section 2.2.2); only oversized UDP errors omit them.
    // Re-sign without changing BADTIME's error or client time (RFC 8945, Section 5.2.3).
    build(true)
        .or_else(|error| {
            if limit.is_udp() {
                build(false)
            } else {
                Err(error)
            }
        })
        .map_err(|source| TsigError::BuildResponse { rcode, source })
}

/// Echo the question when it fits; a compact UDP error retains the request header.
fn build_error_header(
    message: &Message<&[u8]>,
    include_question: bool,
) -> Result<AdditionalBuilder<TreeCompressor<Vec<u8>>>, LibraryError> {
    let mut builder = message::build_response();

    if include_question {
        return Ok(builder.start_answer(message, Rcode::NOTAUTH)?.additional());
    }

    let header = builder.header_mut();
    header.set_id(message.header().id());
    header.set_opcode(message.header().opcode());
    header.set_rd(message.header().rd());
    header.set_qr(true);
    header.set_rcode(Rcode::NOTAUTH);

    Ok(builder.additional())
}

/// TSIG failures that follow successful MAC validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
) -> Result<Vec<u8>, LibraryError> {
    use domain::base::ToName;

    let request_tsig = message
        .additional()?
        .limit_to::<Tsig<_, _>>()
        .last()
        .ok_or(TsigError::RecordMissing)??;
    let data = request_tsig.data();
    let mut additional = build_error_header(message, include_question)?;
    Edns::from_message(message).push_response_opt(&mut additional, OptRcode::NOTAUTH, None, None);

    // domain 0.12.3 omits OPT and hashes eight Other Data bytes; RFC 8945,
    // Section 4.3 requires the six carried on the wire.
    let name = key.domain.name().to_canonical_name::<Vec<u8>>();
    let algorithm = key.domain.algorithm().to_name();
    let (rcode, time_signed, other) = match error {
        AuthenticatedError::BadTime => (
            TsigRcode::BADTIME,
            data.time_signed(),
            Some(now.into_octets()),
        ),
        AuthenticatedError::BadTrunc => (TsigRcode::BADTRUNC, now, None),
    };
    let other = other.as_ref().map_or(&[][..], |time| time.as_slice());

    // The request MAC binds this signed error to the request that caused it.
    let mut digest = hmac::Context::with_key(&key.hmac);
    digest.update(&u16::try_from(data.mac().len())?.to_be_bytes());
    digest.update(data.mac());
    digest.update(additional.as_slice());
    tsig::digest_tsig_variables(
        &mut digest,
        name.as_slice(),
        algorithm.as_slice(),
        time_signed,
        data.fudge(),
        rcode,
        other,
    );
    let mac = digest.sign();
    additional.push((
        key.domain.name(),
        Class::ANY,
        0,
        Tsig::new(
            algorithm,
            time_signed,
            data.fudge(),
            mac.as_ref(),
            message.header().id(),
            rcode,
            other,
        )?,
    ))?;

    Ok(additional.finish().into_target())
}

/// Build NOTAUTH with an echoed, unsigned TSIG and empty MAC (RFC 8945, Section 5.3.2).
fn build_unsigned_error_response(
    message: &Message<&[u8]>,
    rcode: TsigRcode,
    include_question: bool,
) -> Result<Vec<u8>, LibraryError> {
    let request_tsig = message
        .additional()?
        .limit_to::<Tsig<_, _>>()
        .last()
        .ok_or(TsigError::RecordMissing)??;

    let mut additional = build_error_header(message, include_question)?;
    Edns::from_message(message).push_response_opt(&mut additional, OptRcode::NOTAUTH, None, None);
    additional.push((
        request_tsig.owner(),
        request_tsig.class(),
        request_tsig.ttl(),
        Tsig::new(
            request_tsig.data().algorithm(),
            request_tsig.data().time_signed(),
            request_tsig.data().fudge(),
            b"",
            message.header().id(),
            rcode,
            b"",
        )?,
    ))?;

    Ok(additional.finish().into_target())
}
