//! TSIG authentication for queries, updates, transfers, and outbound NOTIFY (RFC 8945).

use std::{str::FromStr, sync::Arc};

use base64::Engine;
use domain::{
    base::{
        Message, Rtype, ToName,
        iana::{Class, OptRcode, Rcode, TsigRcode},
        message_builder::AdditionalBuilder,
        name::ParsedName,
    },
    dep::octseq::parse::Parser,
    rdata::tsig::{Time48, Tsig},
    tsig::{
        Algorithm, ClientTransaction, Key, KeyName, KeyStore, ServerError, ServerSequence,
        ServerTransaction,
    },
};
use ring::hmac;
use thiserror::Error;

use crate::{
    dns::{
        LibraryError,
        message::{Edns, RECORD_FIELDS_LEN},
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

/// Context for signing the response to a validated TSIG request.
pub type ResponseSigner = ServerTransaction<TsigSigningKey>;

/// Context for signing the envelopes of one transfer, which share a running
/// MAC chain (RFC 8945, Section 5.3.1).
pub type TransferSigner = ServerSequence<TsigSigningKey>;

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

/// An outbound transaction and its request MAC for BADTIME verification.
#[derive(Debug)]
pub struct RequestSigner {
    context: ClientTransaction<TsigSigningKey>,
    key: TsigSigningKey,
    request_mac: Vec<u8>,
}

/// Sign a request bindizr is about to send (RFC 8945, Section 5.1) and
/// return the context that checks its answer.
pub fn sign_request(
    builder: &mut AdditionalBuilder<Vec<u8>>,
    key: TsigSigningKey,
) -> Result<RequestSigner, SignRequestError> {
    let context = ClientTransaction::request(key.clone(), builder, Time48::now())
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
    Ok(RequestSigner {
        context,
        key,
        request_mac: tsig.data().mac().to_vec(),
    })
}

/// Check the answer to a signed request against the key that signed it
/// (RFC 8945, Section 5.4.2).
pub fn verify_response(signer: &RequestSigner, response: &[u8]) -> Result<(), VerifyResponseError> {
    let mut message = Message::from_octets(response.to_vec())
        .map_err(|e| VerifyResponseError::Malformed(Box::new(e)))?;
    let tsig_fields = message.additional().ok().and_then(|additional| {
        additional
            .limit_to::<Tsig<_, _>>()
            .last()?
            .ok()
            .map(|tsig| (tsig.data().mac().len(), tsig.data().error()))
    });
    if message.header().rcode() == Rcode::NOTAUTH
        && tsig_fields.is_some_and(|(_, error)| error == TsigRcode::BADTIME)
    {
        return verify_badtime_response(signer, response);
    }
    signer
        .context
        .answer(&mut message, Time48::now())
        .map_err(|error| VerifyResponseError::Rejected(Box::new(error)))?;
    if tsig_fields.map(|(len, _)| len) != Some(signer.key.as_ref().native_len()) {
        return Err(VerifyResponseError::TruncatedMac);
    }
    if let Some((_, error)) = tsig_fields
        && error != TsigRcode::NOERROR
    {
        return Err(VerifyResponseError::ServerError(error));
    }
    Ok(())
}

/// Verify BADTIME's six-byte Other Data (RFC 8945, Section 4.3).
/// domain 0.12.3 incorrectly hashes eight bytes.
fn verify_badtime_response(
    signer: &RequestSigner,
    response: &[u8],
) -> Result<(), VerifyResponseError> {
    let rejected = |error| VerifyResponseError::Rejected(Box::new(error));
    if !matches!(request_signature(response), RequestSignature::Key { .. }) {
        return Err(rejected(domain::tsig::ValidationError::FormErr));
    }
    let message =
        Message::from_octets(response).map_err(|e| VerifyResponseError::Malformed(Box::new(e)))?;
    let mut additional = message
        .additional()
        .map_err(|e| VerifyResponseError::Malformed(Box::new(e)))?;
    let mut tsig_start = additional.pos();
    while let Some(record) = additional.next() {
        let record = record.map_err(|e| VerifyResponseError::Malformed(Box::new(e)))?;
        if record.rtype() == Rtype::TSIG {
            break;
        }
        tsig_start = additional.pos();
    }
    let tsig = message
        .additional()
        .map_err(|e| VerifyResponseError::Malformed(Box::new(e)))?
        .limit_to::<Tsig<_, _>>()
        .last()
        .ok_or_else(|| rejected(domain::tsig::ValidationError::ServerUnsigned))?
        .map_err(|e| VerifyResponseError::Malformed(Box::new(e)))?;
    let data = tsig.data();
    if !tsig.owner().name_eq(signer.key.domain.name())
        || !data
            .algorithm()
            .name_eq(&signer.key.domain.algorithm().to_name())
    {
        return Err(rejected(domain::tsig::ValidationError::BadKey));
    }
    let mut digest = (signer.request_mac.len() as u16).to_be_bytes().to_vec();
    digest.extend_from_slice(&signer.request_mac);
    let mut unsigned = response[..tsig_start].to_vec();
    unsigned[..2].copy_from_slice(&data.original_id().to_be_bytes());
    unsigned[10..12].copy_from_slice(&(message.header_counts().arcount() - 1).to_be_bytes());
    digest.extend_from_slice(&unsigned);
    tsig.owner()
        .compose_canonical(&mut digest)
        .expect("a Vec holds a name");
    digest.extend_from_slice(&Class::ANY.to_int().to_be_bytes());
    digest.extend_from_slice(&0u32.to_be_bytes());
    data.algorithm()
        .compose_canonical(&mut digest)
        .expect("a Vec holds a name");
    digest.extend_from_slice(&data.time_signed().into_octets());
    digest.extend_from_slice(&data.fudge().to_be_bytes());
    digest.extend_from_slice(&data.error().to_int().to_be_bytes());
    digest.extend_from_slice(&(data.other().len() as u16).to_be_bytes());
    digest.extend_from_slice(data.other());
    hmac::verify(&signer.key.hmac, &digest, data.mac())
        .map_err(|_| rejected(domain::tsig::ValidationError::BadSig))?;
    let server = data
        .other_time()
        .ok_or_else(|| rejected(domain::tsig::ValidationError::FormErr))?;
    Err(VerifyResponseError::ServerBadTime(Box::new(
        domain::tsig::ValidationError::ServerBadTime {
            client: data.time_signed(),
            server,
        },
    )))
}

/// Reserve the maximum TSIG size: longest key name, `hmac-sha512.`,
/// 64-byte MAC and 6-byte BADTIME data (RFC 8945, Section 4.2).
pub(crate) const MAX_TSIG_RECORD: usize =
    MAX_WIRE_NAME_LEN + RECORD_FIELDS_LEN + (13 + 6 + 2 + 2 + 64 + 2 + 2 + 2 + 6);

/// Bytes a signed message must leave for its TSIG record.
pub(crate) fn signature_len(signer: &TransferSigner) -> usize {
    usize::from(signer.key().compose_len())
}

/// Store holding the one key the request names, or nothing when that key is
/// unknown so validation yields the BADKEY error response.
#[derive(Debug, Clone)]
struct RequestKeyStore(Option<TsigSigningKey>);

impl KeyStore for RequestKeyStore {
    type Key = TsigSigningKey;

    /// Find a stored TSIG key matching the requested name and algorithm.
    fn get_key<N: ToName>(&self, name: &N, algorithm: Algorithm) -> Option<Self::Key> {
        self.0.as_ref().and_then(|key| key.get_key(name, algorithm))
    }
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

/// Verify MAC and Time Signed/Fudge, returning a response signer or BADKEY for an unknown key.
/// Omit the latest-time cache to accept reordered requests (RFC 8945, Section 5.2.3 SHOULD exception).
pub fn verify_tsig(
    query_data: &[u8],
    key: Option<TsigSigningKey>,
) -> Result<ResponseSigner, TsigError> {
    let original =
        Message::from_octets(query_data).map_err(|e| TsigError::Malformed(Box::new(e)))?;
    // The digest takes the canonical algorithm name (RFC 8945, Section 4.3.3), so
    // any case is valid on the wire (RFC 1035, Section 2.3.3); `domain` matches bytes.
    let mut octets = query_data.to_vec();
    if let Some(range) = tsig_algorithm_name_range(&original) {
        octets[range].make_ascii_lowercase();
    }
    let mut message =
        Message::from_octets(octets).map_err(|e| TsigError::Malformed(Box::new(e)))?;

    let store = RequestKeyStore(key);
    let now = Time48::now();
    match ServerTransaction::request(&store, &mut message, now) {
        Ok(Some(context)) => {
            let key = store.0.as_ref().ok_or(TsigError::RecordMissing)?;
            let tsig = original
                .additional()
                .map_err(|e| TsigError::Malformed(Box::new(e)))?
                .limit_to::<Tsig<_, _>>()
                .last()
                .ok_or(TsigError::RecordMissing)?
                .map_err(|e| TsigError::Malformed(Box::new(e)))?;
            if tsig.data().mac().len() < key.domain.native_len() {
                let response =
                    build_signed_error_response(&original, key, AuthenticatedError::BadTrunc, now)
                        .ok_or(TsigError::BuildResponse {
                            rcode: TsigRcode::BADTRUNC,
                        })?;
                return Err(TsigError::Rejected {
                    rcode: TsigRcode::BADTRUNC,
                    response,
                });
            }
            Ok(context)
        }
        Ok(None) => Err(TsigError::RecordMissing),
        Err(err) => Err(tsig_error(query_data, err, store.0.as_ref(), now)),
    }
}

/// How a request presents itself for authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSignature {
    /// No TSIG record: the address decides, as it did before keys existed.
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
    // RFC 8945, Section 5.2: TSIG is legal only at the end of Additional.
    for section in [message.answer(), message.authority()] {
        let Ok(section) = section else {
            return RequestSignature::Malformed;
        };
        for record in section {
            if !record.is_ok_and(|record| record.rtype() != Rtype::TSIG) {
                return RequestSignature::Malformed;
            }
        }
    }
    let Ok(additional) = message.additional() else {
        return RequestSignature::Malformed;
    };
    // A record that does not parse hides everything after it, so absence can
    // only be concluded from a section read whole.
    let mut records = 0usize;
    let mut tsig_positions = Vec::new();
    for record in additional {
        match record {
            Ok(record) => {
                if record.rtype() == Rtype::TSIG {
                    // RFC 8945, Section 4.2: these fields are fixed, not MAC inputs.
                    if record.class() != Class::ANY || record.ttl().as_secs() != 0 {
                        return RequestSignature::Malformed;
                    }
                    tsig_positions.push(records);
                }
                records += 1;
            }
            Err(_) => return RequestSignature::Malformed,
        }
    }
    match tsig_positions[..] {
        [] => return RequestSignature::Absent,
        [last] if last + 1 == records => {}
        _ => return RequestSignature::Malformed,
    }
    match additional.limit_to::<Tsig<_, _>>().last() {
        Some(Ok(tsig))
            if is_mac_size_in_bounds(tsig.data().algorithm(), tsig.data().mac().len()) =>
        {
            RequestSignature::Key {
                name: tsig.owner().to_string(),
                fudge: tsig.data().fudge(),
            }
        }
        _ => RequestSignature::Malformed,
    }
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

/// Locate the TSIG RDATA's algorithm name, or `None` when the message has no
/// TSIG record or the name is compressed (its octets may then be signed data).
fn tsig_algorithm_name_range(message: &Message<&[u8]>) -> Option<std::ops::Range<usize>> {
    let octets = message.as_slice();
    let mut section = message.additional().ok()?;
    loop {
        let start = section.pos();
        let record = section.next()?.ok()?;
        if record.rtype() != Rtype::TSIG {
            continue;
        }
        let mut parser = Parser::from_ref(octets);
        parser.seek(start).ok()?;
        ParsedName::skip(&mut parser).ok()?;
        parser.advance(RECORD_FIELDS_LEN).ok()?;
        let name_start = parser.pos();
        let mut end = name_start;
        loop {
            let len = usize::from(*octets.get(end)?);
            if len == 0 {
                return Some(name_start..end);
            }
            if len >= 0xC0 {
                return None;
            }
            end += 1 + len;
        }
    }
}

/// Map a TSIG validation failure to the complete NOTAUTH response to send.
fn tsig_error(
    query_data: &[u8],
    err: ServerError<TsigSigningKey>,
    key: Option<&TsigSigningKey>,
    now: Time48,
) -> TsigError {
    let msg = match Message::from_octets(query_data) {
        Ok(msg) => msg,
        Err(e) => return TsigError::Malformed(Box::new(e)),
    };

    // `domain::tsig::server_request` maps bad MACs to FORMERR through 0.12.3;
    // the structure was checked before verification, so that is BADSIG.
    let error = match err.error() {
        TsigRcode::FORMERR => TsigRcode::BADSIG,
        error => error,
    };
    let response = match error {
        // BADTIME is returned only after the request MAC has been authenticated.
        TsigRcode::BADTIME => key.and_then(|key| {
            build_signed_error_response(&msg, key, AuthenticatedError::BadTime, now)
        }),
        other => build_unsigned_error_response(&msg, other),
    };

    match response {
        Some(response) => TsigError::Rejected {
            rcode: error,
            response,
        },
        None => TsigError::BuildResponse { rcode: error },
    }
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
) -> Option<Vec<u8>> {
    let request_tsig = msg
        .additional()
        .ok()?
        .limit_to::<Tsig<_, _>>()
        .last()?
        .ok()?;
    let request = request_tsig.data();
    let mut builder = crate::dns::message::response_builder()
        .start_answer(msg, Rcode::NOTAUTH)
        .ok()?
        .additional();
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
fn build_unsigned_error_response(msg: &Message<&[u8]>, error: TsigRcode) -> Option<Vec<u8>> {
    let tsig_record = msg
        .additional()
        .ok()?
        .limit_to::<Tsig<_, _>>()
        .last()?
        .ok()?;

    let builder = crate::dns::message::response_builder()
        .start_answer(msg, Rcode::NOTAUTH)
        .ok()?;
    let mut builder = builder.additional();
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
