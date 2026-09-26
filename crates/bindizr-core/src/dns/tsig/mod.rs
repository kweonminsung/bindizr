//! TSIG authentication (RFC 8945), backed by `domain::tsig`: verifying a
//! signed request and signing what answers it. One request-one response for
//! nsupdate and SOA; a sequence for the envelopes of a zone transfer; and
//! the client side of it for the NOTIFY bindizr sends.

use std::{str::FromStr, sync::Arc};

use base64::Engine;
use domain::{
    base::{
        Message, MessageBuilder, Rtype, ToName,
        iana::{Rcode, TsigRcode},
        message_builder::AdditionalBuilder,
    },
    rdata::tsig::{Time48, Tsig},
    tsig::{
        Algorithm, ClientTransaction, Key, KeyName, KeyStore, ServerError, ServerSequence,
        ServerTransaction,
    },
};

use crate::{
    dns::name::MAX_DOMAIN_LEN,
    model::tsig_key::{TsigAlgorithm, TsigKey},
};

/// Why a TSIG-signed request could not be accepted.
#[derive(Debug)]
pub enum TsigError {
    /// The request could not be read as a DNS message.
    Malformed(String),
    /// Stored key material, or building the error response, failed.
    Internal(String),
    /// Validation failed; carries the complete NOTAUTH response to send.
    Failed { message: String, response: Vec<u8> },
}

/// Context for signing the response to a validated TSIG request.
pub type ResponseSigner = ServerTransaction<Arc<Key>>;

/// Context for signing the envelopes of one transfer, which share a running
/// MAC chain (RFC 8945, Section 5.3.1).
pub type TransferSigner = ServerSequence<Arc<Key>>;

/// A stored key in the form `domain` signs and verifies with.
pub type TsigSigningKey = Arc<Key>;

/// Context for checking the one answer to a request this side signed.
pub type RequestSigner = ClientTransaction<Arc<Key>>;

/// Sign a request bindizr is about to send (RFC 8945, Section 5.1) and
/// return the context that checks its answer.
pub fn sign_request(
    builder: &mut AdditionalBuilder<Vec<u8>>,
    key: TsigSigningKey,
) -> Result<RequestSigner, String> {
    ClientTransaction::request(key, builder, Time48::now())
        .map_err(|e| format!("failed to sign the request: {}", e))
}

/// Check the answer to a signed request against the key that signed it
/// (RFC 8945, Section 5.4.2).
pub fn verify_response(signer: &RequestSigner, response: &[u8]) -> Result<(), String> {
    let mut message = Message::from_octets(response.to_vec())
        .map_err(|e| format!("invalid DNS message: {}", e))?;
    signer
        .answer(&mut message, Time48::now())
        .map_err(|e| format!("TSIG validation of the answer failed: {}", e))
}

/// The largest TSIG record a response can carry, so an intake cap can reserve
/// room for one it has not seen yet: the longest key name, `hmac-sha512.`, its
/// 64-byte MAC, and the 6 bytes BADTIME adds (RFC 8945, Section 4.2).
pub(crate) const MAX_TSIG_RECORD: usize =
    (MAX_DOMAIN_LEN + 2) + (2 + 2 + 4 + 2) + (13 + 6 + 2 + 2 + 64 + 2 + 2 + 2 + 6);

/// Bytes a signed message must leave for its TSIG record.
pub(crate) fn signature_len(signer: &TransferSigner) -> usize {
    usize::from(signer.key().compose_len())
}

/// Store holding the one key the request names, or nothing when that key is
/// unknown so validation yields the BADKEY error response.
struct DbKeyStore(Option<Arc<Key>>);

impl KeyStore for DbKeyStore {
    type Key = Arc<Key>;

    /// Find a stored TSIG key matching the requested name and algorithm.
    fn get_key<N: ToName>(&self, name: &N, algorithm: Algorithm) -> Option<Self::Key> {
        self.0.as_ref().and_then(|key| key.get_key(name, algorithm))
    }
}

impl TsigKey {
    /// Convert this stored TSIG key into a `domain` signing key.
    pub fn to_domain_key(&self) -> Result<Arc<Key>, TsigError> {
        let name = KeyName::from_str(&self.name).map_err(|e| {
            TsigError::Internal(format!("invalid TSIG key name '{}': {}", self.name, e))
        })?;

        let algorithm = match self.algorithm {
            TsigAlgorithm::HmacSha256 => Algorithm::Sha256,
            TsigAlgorithm::HmacSha384 => Algorithm::Sha384,
            TsigAlgorithm::HmacSha512 => Algorithm::Sha512,
        };

        let secret = base64::engine::general_purpose::STANDARD
            .decode(&self.secret)
            .map_err(|e| {
                TsigError::Internal(format!("stored TSIG secret is not valid base64: {}", e))
            })?;
        if secret.is_empty() {
            return Err(TsigError::Internal(
                "stored TSIG secret decodes to an empty key".to_string(),
            ));
        }

        Key::new(algorithm, &secret, name, None, None)
            .map(Arc::new)
            .map_err(|e| TsigError::Internal(format!("invalid TSIG key '{}': {}", self.name, e)))
    }
}

/// Verify a TSIG-signed request against the key it names (RFC 8945) and return
/// the context for signing its one response. `key` is `None` for an unknown
/// key, which yields the BADKEY error response.
pub fn verify_tsig(query_data: &[u8], key: Option<Arc<Key>>) -> Result<ResponseSigner, TsigError> {
    verify(query_data, key, ServerTransaction::request)
}

/// The same verification for a request answered by many messages, whose
/// signing context carries the MAC chain across them.
pub fn verify_tsig_sequence(
    query_data: &[u8],
    key: Option<Arc<Key>>,
) -> Result<TransferSigner, TsigError> {
    verify(query_data, key, ServerSequence::request)
}

/// Verify a request's TSIG and return the authenticated signing context.
fn verify<T>(
    query_data: &[u8],
    key: Option<Arc<Key>>,
    request: impl FnOnce(
        &DbKeyStore,
        &mut Message<Vec<u8>>,
        Time48,
    ) -> Result<Option<T>, ServerError<Arc<Key>>>,
) -> Result<T, TsigError> {
    let mut message = Message::from_octets(query_data.to_vec())
        .map_err(|e| TsigError::Malformed(format!("invalid DNS message: {}", e)))?;

    match request(&DbKeyStore(key), &mut message, Time48::now()) {
        Ok(Some(context)) => Ok(context),
        // The caller checked for a TSIG record, so `domain` must find one too.
        Ok(None) => Err(TsigError::Internal(
            "TSIG record not found during validation".to_string(),
        )),
        Err(err) => Err(tsig_error(query_data, err)),
    }
}

/// How a request presents itself for authorization.
pub enum RequestSignature {
    /// No TSIG record: the address decides, as it did before keys existed.
    Absent,
    /// A TSIG record that does not parse. Never treated as unsigned — a
    /// caller that reaches for a key must be held to it.
    Malformed,
    /// The key name the record carries.
    Key(String),
}

/// Read how the message is signed. Presence is decided on the record's type
/// alone, so a malformed TSIG cannot pass itself off as an unsigned request.
pub fn request_signature(query_data: &[u8]) -> RequestSignature {
    let Ok(message) = Message::from_octets(query_data) else {
        return RequestSignature::Absent;
    };
    let Ok(additional) = message.additional() else {
        return RequestSignature::Malformed;
    };
    // A record that does not parse hides everything after it, so absence can
    // only be concluded from a section read whole.
    let mut carries_tsig = false;
    for record in additional {
        match record {
            Ok(record) => carries_tsig |= record.rtype() == Rtype::TSIG,
            Err(_) => return RequestSignature::Malformed,
        }
    }
    if !carries_tsig {
        return RequestSignature::Absent;
    }
    match additional.limit_to::<Tsig<_, _>>().last() {
        Some(Ok(tsig)) => RequestSignature::Key(tsig.owner().to_string()),
        _ => RequestSignature::Malformed,
    }
}

/// Map a TSIG validation failure to the complete NOTAUTH response to send.
fn tsig_error(query_data: &[u8], err: ServerError<Arc<Key>>) -> TsigError {
    let msg = match Message::from_octets(query_data) {
        Ok(msg) => msg,
        Err(e) => return TsigError::Internal(format!("invalid DNS message: {}", e)),
    };

    let error = err.error();
    // `domain` folds a MAC mismatch into FORMERR (`ValidationError::BadSig`
    // has no arm in `server_request`, through at least 0.12.2), but the parser
    // already validated the TSIG structure, so FORMERR here can only mean a
    // bad signature — which RFC 8945, Section 5.3.2 requires reporting as BADSIG.
    let response = if error == TsigRcode::FORMERR {
        build_unsigned_error(&msg, TsigRcode::BADSIG)
    } else {
        err.build_message(&msg, MessageBuilder::new_vec())
            .ok()
            .map(|builder| builder.finish())
    };

    match response {
        Some(response) => TsigError::Failed {
            message: format!("TSIG validation failed: {}", error),
            response,
        },
        None => TsigError::Internal(format!("failed to build TSIG error response ({})", error)),
    }
}

/// Build a NOTAUTH response carrying an unsigned TSIG error record that
/// echoes the request TSIG with an empty MAC (RFC 8945, Section 5.3.2).
fn build_unsigned_error(msg: &Message<&[u8]>, error: TsigRcode) -> Option<Vec<u8>> {
    let tsig_record = msg
        .additional()
        .ok()?
        .limit_to::<Tsig<_, _>>()
        .last()?
        .ok()?;

    let builder = MessageBuilder::new_vec()
        .start_answer(msg, Rcode::NOTAUTH)
        .ok()?;
    let mut builder = builder.additional();
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

    Some(builder.finish())
}

#[cfg(test)]
pub(crate) mod tests;
