//! TSIG authentication for queries, updates, transfers, and outbound NOTIFY (RFC 8945).

mod record;
mod response;
mod signer;

use std::sync::Arc;

use base64::DecodeError;
use base64::engine::general_purpose;
use domain::base::iana::{Class, Rcode, TsigRcode};
use domain::base::message_builder::AdditionalBuilder;
use domain::base::{Message, ToName};
use domain::rdata::tsig::{Time48, Tsig};
use domain::tsig::{Algorithm, ClientTransaction, Key, KeyName, ValidationError};
pub use response::build_error_response;
use ring::hmac;
pub use signer::{ResponseSigner, SignResponseError, TransferSigner};
use thiserror::Error;

use crate::dns::LibraryError;
use crate::dns::message::RECORD_FIELDS_LEN;
use crate::dns::name::MAX_WIRE_NAME_LEN;
use crate::dns::tsig::record::ParsedTsig;
use crate::model::tsig_key::{TsigAlgorithm, TsigKey};

/// Reserve the maximum TSIG size: longest key name, `hmac-sha512.`,
/// 64-byte MAC and 6-byte BADTIME data (RFC 8945, Section 4.2).
pub(crate) const MAX_TSIG_RECORD: usize =
    MAX_WIRE_NAME_LEN + RECORD_FIELDS_LEN + (13 + 6 + 2 + 2 + 64 + 2 + 2 + 2 + 6);

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
    SecretNotBase64(#[source] DecodeError),
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
    #[error("failed to build TSIG error response ({rcode}): {source}")]
    BuildResponse {
        rcode: TsigRcode,
        #[source]
        source: LibraryError,
    },
    /// Validation failed; authenticated errors retain the key and server time for the encoder.
    #[error("TSIG validation failed: {rcode}")]
    Rejected {
        rcode: TsigRcode,
        key: Option<Box<TsigSigningKey>>,
        time: Time48,
    },
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
    #[error("authenticated TSIG server error: {rcode}")]
    ServerError { rcode: TsigRcode },
    #[error("TSIG response MAC is shorter than the full-length policy permits")]
    TruncatedMac,
}

impl VerifyResponseError {
    /// Return whether MAC validation authenticated the server error.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::ServerBadTime(_) | Self::ServerError { .. })
    }
}

/// Validated key material for transactions and signed TSIG errors.
#[derive(Debug, Clone)]
pub struct TsigSigningKey {
    domain: Arc<Key>,
    hmac: hmac::Key,
}

impl AsRef<Key> for TsigSigningKey {
    /// Return the key used by the transaction and sequence signers.
    fn as_ref(&self) -> &Key {
        &self.domain
    }
}

/// The outbound key and request MAC used to authenticate the response.
#[derive(Debug, Clone)]
pub struct ResponseVerifier {
    key: TsigSigningKey,
    request_mac: Vec<u8>,
}

/// Sign a request bindizr is about to send (RFC 8945, Section 5.1) and
/// return the context that checks its answer.
pub fn sign_request(
    additional: &mut AdditionalBuilder<Vec<u8>>,
    key: TsigSigningKey,
) -> Result<ResponseVerifier, SignRequestError> {
    ClientTransaction::request(key.clone(), additional, Time48::now())
        .map_err(|error| SignRequestError(Box::new(error)))?;
    let message = Message::from_octets(additional.as_slice())
        .map_err(|error| SignRequestError(Box::new(error)))?;
    let tsig = message
        .additional()
        .map_err(|error| SignRequestError(Box::new(error)))?
        .limit_to::<Tsig<_, _>>()
        .last()
        .ok_or_else(|| SignRequestError(Box::new(TsigError::RecordMissing)))?
        .map_err(|error| SignRequestError(Box::new(error)))?;

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
    let message = Message::from_octets(response)
        .map_err(|error| VerifyResponseError::Malformed(Box::new(error)))?;
    let tsig = ParsedTsig::parse(&message)
        .map_err(|error| VerifyResponseError::Malformed(Box::new(error)))?
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

    // Authenticate the MAC before trusting server-reported TSIG errors.
    tsig.verify_mac(&verifier.key, &message, Some(&verifier.request_mac))
        .map_err(|error| VerifyResponseError::Rejected(Box::new(error)))?;

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
        return Err(VerifyResponseError::ServerError {
            rcode: data.error(),
        });
    }

    Ok(())
}

impl TsigKey {
    /// Decode and validate this stored key for TSIG signing and verification.
    pub fn to_signing_key(&self) -> Result<TsigSigningKey, TsigError> {
        use std::str::FromStr;

        use base64::Engine;

        let name = KeyName::from_str(&self.name).map_err(|error| TsigError::InvalidKeyName {
            name: self.name.clone(),
            source: Box::new(error),
        })?;

        let algorithm = Algorithm::from(self.algorithm);
        let hmac_algorithm = match self.algorithm {
            TsigAlgorithm::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            TsigAlgorithm::HmacSha256 => hmac::HMAC_SHA256,
            TsigAlgorithm::HmacSha384 => hmac::HMAC_SHA384,
            TsigAlgorithm::HmacSha512 => hmac::HMAC_SHA512,
        };

        let secret = general_purpose::STANDARD
            .decode(&self.secret)
            .map_err(TsigError::SecretNotBase64)?;

        if secret.is_empty() {
            return Err(TsigError::EmptySecret);
        }

        // RFC 8945, Section 5.2: authenticate the MAC before checking local length policy.
        let domain = Key::new(
            algorithm,
            &secret,
            name,
            Some(minimum_mac_len(algorithm)),
            None,
        )
        .map_err(|error| TsigError::InvalidKey {
            name: self.name.clone(),
            source: Box::new(error),
        })?;

        Ok(TsigSigningKey {
            domain: Arc::new(domain),
            hmac: hmac::Key::new(hmac_algorithm, &secret),
        })
    }
}

/// Verify a request's TSIG and return its signer or validation error.
/// Accept reordered requests without a time cache (RFC 8945, Section 5.2.3 SHOULD exception).
pub fn verify_tsig(
    query_data: &[u8],
    key: Option<TsigSigningKey>,
) -> Result<ResponseSigner, TsigError> {
    let message =
        Message::from_octets(query_data).map_err(|error| TsigError::Malformed(Box::new(error)))?;
    let malformed = || TsigError::Malformed(Box::new(ValidationError::FormErr));
    let tsig = ParsedTsig::parse(&message)
        .map_err(|error| TsigError::Malformed(Box::new(error)))?
        .ok_or(TsigError::RecordMissing)?;
    let data = tsig.record.data();

    if !is_request_tsig_valid(data) {
        return Err(malformed());
    }

    let now = Time48::now();
    let rejected = |rcode, key: Option<TsigSigningKey>| TsigError::Rejected {
        rcode,
        key: key.map(Box::new),
        time: now,
    };
    let Some(key) = key.filter(|key| tsig.matches_key(key)) else {
        return Err(rejected(TsigRcode::BADKEY, None));
    };

    // RFC 8945, Section 5.2: key, MAC, time, then local truncation policy.
    if tsig.verify_mac(&key, &message, None).is_err() {
        return Err(rejected(TsigRcode::BADSIG, None));
    }
    if !data.is_valid_at(now) {
        return Err(rejected(TsigRcode::BADTIME, Some(key)));
    }
    if data.mac().len() < key.domain.native_len() {
        return Err(rejected(TsigRcode::BADTRUNC, Some(key)));
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
    Key(RequestTsig),
}

/// The key name a request's TSIG carries, and the fudge its answer echoes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTsig {
    pub name: String,
    pub fudge: u16,
}

/// Read how the message is signed. Presence is decided on the record's type
/// alone, so a malformed TSIG cannot pass itself off as an unsigned request.
pub fn request_signature(query_data: &[u8]) -> RequestSignature {
    let Ok(message) = Message::from_octets(query_data) else {
        return RequestSignature::Absent;
    };

    match ParsedTsig::parse(&message) {
        Ok(None) => RequestSignature::Absent,
        Ok(Some(tsig)) if is_request_tsig_valid(tsig.record.data()) => {
            RequestSignature::Key(RequestTsig {
                name: tsig.record.owner().to_string(),
                fudge: tsig.record.data().fudge(),
            })
        }
        _ => RequestSignature::Malformed,
    }
}

/// Return whether a request's Error is zero and its MAC length obeys the
/// algorithm's wire bounds (RFC 8945, Section 4.2).
pub(crate) fn is_request_tsig_valid<O: AsRef<[u8]>, N: ToName>(tsig: &Tsig<O, N>) -> bool {
    tsig.error() == TsigRcode::NOERROR
        && is_mac_size_in_bounds(tsig.algorithm(), tsig.mac().as_ref().len())
}

/// Return whether a MAC length lies from max(10, half the hash length) to the full length
/// (RFC 8945, Section 5.2.2.1); defer unknown algorithms to the BADKEY check.
pub(crate) fn is_mac_size_in_bounds<N: ToName>(algorithm: &N, mac_len: usize) -> bool {
    let Some(algorithm) = algorithm_from_name(algorithm) else {
        return true;
    };
    mac_len <= algorithm.native_len() && mac_len >= minimum_mac_len(algorithm)
}

/// Return the shortest MAC an algorithm accepts: half its hash length, but
/// never under 10 octets (RFC 8945, Section 5.2.2.1).
fn minimum_mac_len(algorithm: Algorithm) -> usize {
    10.max(algorithm.native_len() / 2)
}

/// Feed the TSIG variables to a MAC digest (RFC 8945, Section 4.3.3): the key
/// name and algorithm in canonical form, class ANY, TTL zero, the time, fudge
/// and error, and the Other Data after its length. Other Data is read from a
/// TSIG record or is the six-octet server time, so its length fits Other Len.
pub(crate) fn digest_tsig_variables(
    digest: &mut hmac::Context,
    name: &[u8],
    algorithm: &[u8],
    time_signed: Time48,
    fudge: u16,
    error: TsigRcode,
    other: &[u8],
) {
    digest.update(name);
    digest.update(&Class::ANY.to_int().to_be_bytes());
    digest.update(&0u32.to_be_bytes());
    digest.update(algorithm);
    digest.update(&time_signed.into_octets());
    digest.update(&fudge.to_be_bytes());
    digest.update(&error.to_int().to_be_bytes());
    digest.update(&(other.len() as u16).to_be_bytes());
    digest.update(other);
}

/// Match a supported algorithm name through [`TsigAlgorithm`]'s parser, which
/// ignores ASCII case (RFC 1035, Section 2.3.3) where
/// `domain::tsig::Algorithm::from_name` compares bytes.
fn algorithm_from_name<N: ToName>(name: &N) -> Option<Algorithm> {
    let mut labels = name.iter_labels();
    let first = labels.next()?;

    if !labels.next()?.is_root() || labels.next().is_some() {
        return None;
    }

    let algorithm = str::from_utf8(first.as_slice())
        .ok()?
        .parse::<TsigAlgorithm>()
        .ok()?;

    Some(Algorithm::from(algorithm))
}

impl From<TsigAlgorithm> for Algorithm {
    /// Convert a stored algorithm into the `domain` crate's TSIG algorithm.
    fn from(algorithm: TsigAlgorithm) -> Self {
        match algorithm {
            TsigAlgorithm::HmacSha1 => Self::Sha1,
            TsigAlgorithm::HmacSha256 => Self::Sha256,
            TsigAlgorithm::HmacSha384 => Self::Sha384,
            TsigAlgorithm::HmacSha512 => Self::Sha512,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
