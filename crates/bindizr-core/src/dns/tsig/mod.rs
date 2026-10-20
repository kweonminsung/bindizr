//! TSIG authentication for queries, updates, transfers, and outbound NOTIFY (RFC 8945).

mod record;
mod signer;

use std::{str::FromStr, sync::Arc};

use base64::Engine;
use domain::{
    base::{
        Message, ToName,
        iana::{Class, OptRcode, Rcode, TsigRcode},
        message_builder::{AdditionalBuilder, TreeCompressor},
    },
    rdata::tsig::{Time48, Tsig},
    tsig::{Algorithm, ClientTransaction, Key, KeyName, ValidationError},
};
use record::ParsedTsig;
use ring::hmac;
pub use signer::{ResponseSigner, SignResponseError, TransferSigner};
use thiserror::Error;

use crate::{
    dns::{
        LibraryError,
        message::{Edns, RECORD_FIELDS_LEN, ResponseLimit},
        name::MAX_WIRE_NAME_LEN,
    },
    model::tsig_key::{TsigAlgorithm, TsigKey},
};

/// Why a TSIG-signed request could not be accepted.
#[derive(Debug, Error)]
pub enum TsigError {
    /// The request could not be read as a DNS message.
    #[error("invalid DNS message: {0}")]
    Malformed(#[source] LibraryError),
    #[error("invalid TSIG key name '{name}': {source}")]
    InvalidKeyName {
        name: String,
        #[source]
        source: LibraryError,
    },
    #[error("stored TSIG secret is not valid base64: {0}")]
    SecretNotBase64(#[source] base64::DecodeError),
    #[error("stored TSIG secret decodes to an empty key")]
    EmptySecret,
    #[error("invalid TSIG key '{name}': {source}")]
    InvalidKey {
        name: String,
        #[source]
        source: LibraryError,
    },
    /// The caller checked for a TSIG record, so `domain` must find one too.
    #[error("TSIG record not found during validation")]
    RecordMissing,
    #[error("failed to build TSIG error response ({rcode})")]
    BuildResponse { rcode: TsigRcode },
    /// Validation failed; carries the complete NOTAUTH response to send.
    #[error("TSIG validation failed: {rcode}")]
    Rejected { rcode: TsigRcode, response: Vec<u8> },
}

/// Signing an outbound request failed.
#[derive(Debug, Error)]
#[error("failed to sign the request: {0}")]
pub struct SignRequestError(#[source] LibraryError);

/// The answer to a signed request did not verify under the key.
#[derive(Debug, Error)]
pub enum VerifyResponseError {
    #[error("invalid DNS message: {0}")]
    Malformed(#[source] LibraryError),
    #[error("TSIG validation of the answer failed: {0}")]
    Rejected(#[source] LibraryError),
    #[error("authenticated TSIG server clock error: {0}")]
    ServerBadTime(#[source] LibraryError),
    #[error("authenticated TSIG server error: {0}")]
    ServerError(TsigRcode),
    #[error("TSIG response MAC is shorter than the full-length policy permits")]
    TruncatedMac,
}

impl VerifyResponseError {
    /// Report whether MAC validation authenticated the server error.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::ServerBadTime(_) | Self::ServerError(_))
    }
}

/// Validated key material for transactions and signed TSIG errors.
#[derive(Clone, Debug)]
pub struct TsigSigningKey {
    domain: Arc<Key>,
    hmac: hmac::Key,
}

impl AsRef<Key> for TsigSigningKey {
    /// Borrow the key used by the transaction and sequence signers.
    fn as_ref(&self) -> &Key {
        &self.domain
    }
}

/// The outbound key and request MAC used to authenticate the response.
#[derive(Clone, Debug)]
pub struct ResponseVerifier {
    key: TsigSigningKey,
    request_mac: Vec<u8>,
}

/// Sign a request bindizr is about to send (RFC 8945, Section 5.1) and
/// return the context that checks its answer.
pub fn sign_request(
    builder: &mut AdditionalBuilder<Vec<u8>>,
    key: TsigSigningKey,
) -> Result<ResponseVerifier, SignRequestError> {
    ClientTransaction::request(key.clone(), builder, Time48::now())
        .map_err(|e| SignRequestError(Box::new(e)))?;
    let message =
        Message::from_octets(builder.as_slice()).map_err(|e| SignRequestError(Box::new(e)))?;
    let tsig = message
        .additional()
        .map_err(|e| SignRequestError(Box::new(e)))?
        .limit_to::<Tsig<_, _>>()
        .last()
        .ok_or_else(|| SignRequestError(Box::new(TsigError::RecordMissing)))?
        .map_err(|e| SignRequestError(Box::new(e)))?;
    Ok(ResponseVerifier {
        key,
        request_mac: tsig.data().mac().to_vec(),
    })
}

/// Check the answer to a signed request against the key that signed it
/// (RFC 8945, Section 5.4.2).
pub fn verify_response(
    verifier: &ResponseVerifier,
    response: &[u8],
) -> Result<(), VerifyResponseError> {
    let rejected = |error| VerifyResponseError::Rejected(Box::new(error));
    let message =
        Message::from_octets(response).map_err(|e| VerifyResponseError::Malformed(Box::new(e)))?;
    let tsig = ParsedTsig::parse(&message)
        .map_err(|e| VerifyResponseError::Malformed(Box::new(e)))?
        .ok_or_else(|| rejected(ValidationError::ServerUnsigned))?;
    let data = tsig.record.data();
    // RFC 8945, Section 5.3.2: these errors carry no authenticated MAC.
    if message.header().rcode() == Rcode::NOTAUTH {
        match data.error() {
            TsigRcode::BADKEY => return Err(rejected(ValidationError::ServerBadKey)),
            TsigRcode::BADSIG => return Err(rejected(ValidationError::ServerBadSig)),
            _ => {}
        }
    }
    if !tsig.matches_key(&verifier.key) {
        return Err(rejected(ValidationError::BadKey));
    }
    if !is_mac_size_in_bounds(data.algorithm(), data.mac().len())
        || (data.error() == TsigRcode::BADTIME && data.other().len() != 6)
        || (data.error() != TsigRcode::BADTIME && !data.other().is_empty())
    {
        return Err(rejected(ValidationError::FormErr));
    }
    tsig.verify_mac(&verifier.key, &message, Some(&verifier.request_mac))
        .map_err(|e| VerifyResponseError::Rejected(Box::new(e)))?;
    if data.mac().len() != verifier.key.as_ref().native_len() {
        return Err(VerifyResponseError::TruncatedMac);
    }
    if message.header().rcode() == Rcode::NOTAUTH && data.error() == TsigRcode::BADTIME {
        let server = data
            .other_time()
            .ok_or_else(|| rejected(ValidationError::FormErr))?;
        return Err(VerifyResponseError::ServerBadTime(Box::new(
            ValidationError::ServerBadTime {
                client: data.time_signed(),
                server,
            },
        )));
    }
    if !data.is_valid_at(Time48::now()) {
        return Err(rejected(ValidationError::BadTime));
    }
    if data.error() != TsigRcode::NOERROR {
        return Err(VerifyResponseError::ServerError(data.error()));
    }
    Ok(())
}

/// Reserve the maximum TSIG size: longest key name, `hmac-sha512.`,
/// 64-byte MAC and 6-byte BADTIME data (RFC 8945, Section 4.2).
pub(crate) const MAX_TSIG_RECORD: usize =
    MAX_WIRE_NAME_LEN + RECORD_FIELDS_LEN + (13 + 6 + 2 + 2 + 64 + 2 + 2 + 2 + 6);

/// Bytes a signed message must leave for its TSIG record.
pub(crate) fn signature_len(signer: &TransferSigner) -> usize {
    usize::from(signer.key().compose_len())
}

impl TsigKey {
    /// Decode and validate this stored key for TSIG signing and verification.
    pub fn to_signing_key(&self) -> Result<TsigSigningKey, TsigError> {
        let name = KeyName::from_str(&self.name).map_err(|e| TsigError::InvalidKeyName {
            name: self.name.clone(),
            source: Box::new(e),
        })?;

        let (algorithm, hmac_algorithm) = match self.algorithm {
            TsigAlgorithm::HmacSha1 => (Algorithm::Sha1, hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
            TsigAlgorithm::HmacSha256 => (Algorithm::Sha256, hmac::HMAC_SHA256),
            TsigAlgorithm::HmacSha384 => (Algorithm::Sha384, hmac::HMAC_SHA384),
            TsigAlgorithm::HmacSha512 => (Algorithm::Sha512, hmac::HMAC_SHA512),
        };

        let secret = base64::engine::general_purpose::STANDARD
            .decode(&self.secret)
            .map_err(TsigError::SecretNotBase64)?;
        if secret.is_empty() {
            return Err(TsigError::EmptySecret);
        }

        // RFC 8945, Section 5.2: authenticate the MAC before checking local length policy.
        let min_mac_len = 10.max(algorithm.native_len() / 2);
        let domain = Key::new(algorithm, &secret, name, Some(min_mac_len), None).map_err(|e| {
            TsigError::InvalidKey {
                name: self.name.clone(),
                source: Box::new(e),
            }
        })?;
        Ok(TsigSigningKey {
            domain: Arc::new(domain),
            hmac: hmac::Key::new(hmac_algorithm, &secret),
        })
    }
}

/// Verify TSIG and return a signer or a bounded validation error.
/// Accept reordered requests without a time cache (RFC 8945, Section 5.2.3 SHOULD exception).
pub fn verify_tsig(
    query_data: &[u8],
    key: Option<TsigSigningKey>,
    limit: ResponseLimit,
) -> Result<ResponseSigner, TsigError> {
    let message =
        Message::from_octets(query_data).map_err(|e| TsigError::Malformed(Box::new(e)))?;
    let malformed = || TsigError::Malformed(Box::new(ValidationError::FormErr));
    let tsig = ParsedTsig::parse(&message)
        .map_err(|e| TsigError::Malformed(Box::new(e)))?
        .ok_or(TsigError::RecordMissing)?;
    let data = tsig.record.data();
    if !is_request_tsig_valid(data) {
        return Err(malformed());
    }
    let now = Time48::now();
    let Some(key) = key.filter(|key| tsig.matches_key(key)) else {
        return Err(tsig_error(&message, None, TsigRcode::BADKEY, now, limit));
    };
    // RFC 8945, Section 5.2: key, MAC, time, then local truncation policy.
    if tsig.verify_mac(&key, &message, None).is_err() {
        return Err(tsig_error(&message, None, TsigRcode::BADSIG, now, limit));
    }
    if !data.is_valid_at(now) {
        return Err(tsig_error(
            &message,
            Some(&key),
            TsigRcode::BADTIME,
            now,
            limit,
        ));
    }
    if data.mac().len() < key.domain.native_len() {
        return Err(tsig_error(
            &message,
            Some(&key),
            TsigRcode::BADTRUNC,
            now,
            limit,
        ));
    }
    Ok(ResponseSigner {
        key,
        request_mac: data.mac().to_vec(),
    })
}

/// How a request presents itself for authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSignature {
    /// No TSIG record.
    Absent,
    /// Duplicate, misplaced, undecodable or impossible-length TSIG: answer FORMERR,
    /// never treat as unsigned (RFC 8945, Section 5.2).
    Malformed,
    /// The key name the record carries, and the fudge its answer echoes.
    Key { name: String, fudge: u16 },
}

/// Read how the message is signed. Presence is decided on the record's type
/// alone, so a malformed TSIG cannot pass itself off as an unsigned request.
pub fn request_signature(query_data: &[u8]) -> RequestSignature {
    let Ok(message) = Message::from_octets(query_data) else {
        return RequestSignature::Absent;
    };
    match ParsedTsig::parse(&message) {
        Ok(None) => RequestSignature::Absent,
        Ok(Some(tsig)) if is_request_tsig_valid(tsig.record.data()) => RequestSignature::Key {
            name: tsig.record.owner().to_string(),
            fudge: tsig.record.data().fudge(),
        },
        _ => RequestSignature::Malformed,
    }
}

/// A request's Error is zero; MAC length obeys the algorithm's wire bounds (RFC 8945, Section 4.2).
pub(crate) fn is_request_tsig_valid<O: AsRef<[u8]>, N: ToName>(tsig: &Tsig<O, N>) -> bool {
    tsig.error() == TsigRcode::NOERROR
        && is_mac_size_in_bounds(tsig.algorithm(), tsig.mac().as_ref().len())
}

/// Accept MAC lengths from max(10, half the hash length) to the full length
/// (RFC 8945, Section 5.2.2.1); defer unknown algorithms to the BADKEY check.
pub(crate) fn is_mac_size_in_bounds<N: ToName>(algorithm: &N, mac_len: usize) -> bool {
    let Some(algorithm) = algorithm_from_name(algorithm) else {
        return true;
    };
    let native = algorithm.native_len();
    mac_len <= native && mac_len >= 10.max(native / 2)
}

/// Match a supported algorithm name ignoring ASCII case (RFC 1035, Section
/// 2.3.3), where `domain::tsig::Algorithm::from_name` compares bytes.
fn algorithm_from_name<N: ToName>(name: &N) -> Option<Algorithm> {
    let mut labels = name.iter_labels();
    let first = labels.next()?;
    if !labels.next()?.is_root() || labels.next().is_some() {
        return None;
    }
    [
        ("hmac-sha1", Algorithm::Sha1),
        ("hmac-sha256", Algorithm::Sha256),
        ("hmac-sha384", Algorithm::Sha384),
        ("hmac-sha512", Algorithm::Sha512),
    ]
    .into_iter()
    .find(|(text, _)| first.as_slice().eq_ignore_ascii_case(text.as_bytes()))
    .map(|(_, algorithm)| algorithm)
}

/// Build the signed or unsigned validation error required by RFC 8945, Section 5.3.2.
fn tsig_error(
    message: &Message<&[u8]>,
    key: Option<&TsigSigningKey>,
    error: TsigRcode,
    now: Time48,
    limit: ResponseLimit,
) -> TsigError {
    for include_question in [true, false] {
        // Keep stream questions (RFC 5936, Section 2.2.2); only oversized UDP errors omit them.
        // Re-sign without changing BADTIME's error or client time (RFC 8945, Section 5.2.3).
        if !include_question && !limit.is_udp() {
            break;
        }
        let response = match (error, key) {
            (TsigRcode::BADTIME, Some(key)) => build_signed_error_response(
                message,
                key,
                AuthenticatedError::BadTime,
                now,
                include_question,
            ),
            (TsigRcode::BADTRUNC, Some(key)) => build_signed_error_response(
                message,
                key,
                AuthenticatedError::BadTrunc,
                now,
                include_question,
            ),
            _ => build_unsigned_error_response(message, error, include_question),
        };
        if let Some(response) = response
            && limit.check_len(response.len()).is_ok()
        {
            return TsigError::Rejected {
                rcode: error,
                response,
            };
        }
    }
    TsigError::BuildResponse { rcode: error }
}

/// Echo the question when it fits; a compact UDP error retains the request header.
fn error_response(
    msg: &Message<&[u8]>,
    include_question: bool,
) -> Option<AdditionalBuilder<TreeCompressor<Vec<u8>>>> {
    let mut builder = crate::dns::message::build_response();
    if include_question {
        return Some(builder.start_answer(msg, Rcode::NOTAUTH).ok()?.additional());
    }
    let header = builder.header_mut();
    header.set_id(msg.header().id());
    header.set_opcode(msg.header().opcode());
    header.set_rd(msg.header().rd());
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
    msg: &Message<&[u8]>,
    key: &TsigSigningKey,
    error: AuthenticatedError,
    now: Time48,
    include_question: bool,
) -> Option<Vec<u8>> {
    let request_tsig = msg
        .additional()
        .ok()?
        .limit_to::<Tsig<_, _>>()
        .last()?
        .ok()?;
    let request = request_tsig.data();
    let mut builder = error_response(msg, include_question)?;
    Edns::from_message(msg).push_response(&mut builder, OptRcode::NOTAUTH, None, None);

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
                msg.header().id(),
                rcode,
                other,
            )
            .ok()?,
        ))
        .ok()?;
    Some(builder.finish().into_target())
}

/// Build a NOTAUTH response carrying an unsigned TSIG error record that
/// echoes the request TSIG with an empty MAC (RFC 8945, Section 5.3.2).
fn build_unsigned_error_response(
    msg: &Message<&[u8]>,
    error: TsigRcode,
    include_question: bool,
) -> Option<Vec<u8>> {
    let tsig_record = msg
        .additional()
        .ok()?
        .limit_to::<Tsig<_, _>>()
        .last()?
        .ok()?;

    let mut builder = error_response(msg, include_question)?;
    Edns::from_message(msg).push_response(&mut builder, OptRcode::NOTAUTH, None, None);
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
                msg.header().id(),
                error,
                b"",
            )
            .ok()?,
        ))
        .ok()?;

    Some(builder.finish().into_target())
}

#[cfg(test)]
pub(crate) mod tests;
