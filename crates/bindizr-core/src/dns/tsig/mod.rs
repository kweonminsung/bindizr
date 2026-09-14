//! TSIG authentication (RFC 8945), backed by `domain::tsig`: verifying a
//! signed request and signing what answers it. One request-one response for
//! nsupdate and SOA; a sequence for the envelopes of a zone transfer.

use std::{str::FromStr, sync::Arc};

use base64::Engine;
use domain::{
    base::{
        Message, MessageBuilder, ToName,
        iana::{Rcode, TsigRcode},
    },
    rdata::tsig::{Time48, Tsig},
    tsig::{Algorithm, Key, KeyName, KeyStore, ServerError, ServerSequence, ServerTransaction},
};

use crate::model::tsig_key::{TsigAlgorithm, TsigKey};

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

/// Bytes a signed message must leave for its TSIG record.
pub fn signature_len(signer: &TransferSigner) -> usize {
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

/// Converts a stored TSIG key into a `domain` signing key.
pub fn to_domain_key(key: &TsigKey) -> Result<Arc<Key>, TsigError> {
    let name = KeyName::from_str(&key.name)
        .map_err(|e| TsigError::Internal(format!("invalid TSIG key name '{}': {}", key.name, e)))?;

    let algorithm = match key.algorithm {
        TsigAlgorithm::HmacSha256 => Algorithm::Sha256,
        TsigAlgorithm::HmacSha384 => Algorithm::Sha384,
        TsigAlgorithm::HmacSha512 => Algorithm::Sha512,
    };

    let secret = base64::engine::general_purpose::STANDARD
        .decode(&key.secret)
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
        .map_err(|e| TsigError::Internal(format!("invalid TSIG key '{}': {}", key.name, e)))
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

/// The key a signed message names, or `None` when it carries no TSIG record,
/// which is what chooses between key- and address-authorized handling.
pub fn signed_key_name(query_data: &[u8]) -> Option<String> {
    let message = Message::from_octets(query_data).ok()?;
    let tsig = message.additional().ok()?.limit_to::<Tsig<_, _>>().last()?;
    Some(tsig.ok()?.owner().to_string())
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

/// Build a NOTAUTH response carrying an unsigned TSIG error RR that
/// echoes the request TSIG with an empty MAC (RFC 8945, Section 5.3.2).
fn build_unsigned_error(msg: &Message<&[u8]>, error: TsigRcode) -> Option<Vec<u8>> {
    let tsig_rr = msg
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
            tsig_rr.owner(),
            tsig_rr.class(),
            tsig_rr.ttl(),
            Tsig::new(
                tsig_rr.data().algorithm(),
                tsig_rr.data().time_signed(),
                tsig_rr.data().fudge(),
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
