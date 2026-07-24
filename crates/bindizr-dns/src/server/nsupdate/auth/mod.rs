//! TSIG authentication for nsupdate requests (RFC 8945), backed by
//! `domain::tsig` for verification and response signing.

use std::{str::FromStr, sync::Arc};

use base64::Engine;
use domain::{
    base::{
        Message, MessageBuilder, ToName,
        iana::{Rcode, TsigRcode},
    },
    rdata::tsig::{Time48, Tsig},
    tsig::{Algorithm, Key, KeyName, KeyStore, ServerError, ServerTransaction},
};

use super::update::UpdateError;
use crate::model::tsig_key::{TsigAlgorithm, TsigKey};

/// Context for signing the response to a validated TSIG request.
pub(super) type ResponseSigner = ServerTransaction<Arc<Key>>;

/// Store holding the one key the request names, or nothing when that key is
/// unknown so validation yields the BADKEY error response.
struct DbKeyStore(Option<Arc<Key>>);

impl KeyStore for DbKeyStore {
    type Key = Arc<Key>;

    fn get_key<N: ToName>(&self, name: &N, algorithm: Algorithm) -> Option<Self::Key> {
        self.0.as_ref().and_then(|key| key.get_key(name, algorithm))
    }
}

/// Converts a stored TSIG key into a `domain` signing key.
pub(super) fn to_domain_key(key: &TsigKey) -> Result<Arc<Key>, UpdateError> {
    let name = KeyName::from_str(&key.name).map_err(|e| {
        UpdateError::Internal(format!("invalid TSIG key name '{}': {}", key.name, e))
    })?;

    let algorithm = match key.algorithm {
        TsigAlgorithm::HmacSha256 => Algorithm::Sha256,
        TsigAlgorithm::HmacSha384 => Algorithm::Sha384,
        TsigAlgorithm::HmacSha512 => Algorithm::Sha512,
    };

    let secret = base64::engine::general_purpose::STANDARD
        .decode(&key.secret)
        .map_err(|e| {
            UpdateError::Internal(format!("stored TSIG secret is not valid base64: {}", e))
        })?;
    if secret.is_empty() {
        return Err(UpdateError::Internal(
            "stored TSIG secret decodes to an empty key".to_string(),
        ));
    }

    Key::new(algorithm, &secret, name, None, None)
        .map(Arc::new)
        .map_err(|e| UpdateError::Internal(format!("invalid TSIG key '{}': {}", key.name, e)))
}

/// Verify a TSIG-signed nsupdate request against the key it names (RFC 8945)
/// and return the context for signing the response. `key` is `None` when the
/// named key is unknown, which yields the BADKEY error response.
pub(super) fn validate_tsig(
    query_data: &[u8],
    key: Option<Arc<Key>>,
) -> Result<ResponseSigner, UpdateError> {
    let mut message = Message::from_octets(query_data.to_vec())
        .map_err(|e| UpdateError::Refused(format!("invalid DNS message: {}", e)))?;

    match ServerTransaction::request(&DbKeyStore(key), &mut message, Time48::now()) {
        Ok(Some(transaction)) => Ok(transaction),
        // The parser required a TSIG record, so `domain` must find one too.
        Ok(None) => Err(UpdateError::Internal(
            "TSIG record not found during validation".to_string(),
        )),
        Err(err) => Err(tsig_failure(query_data, err)),
    }
}

/// Map a TSIG validation failure to the complete NOTAUTH response to send.
fn tsig_failure(query_data: &[u8], err: ServerError<Arc<Key>>) -> UpdateError {
    let msg = match Message::from_octets(query_data) {
        Ok(msg) => msg,
        Err(e) => return UpdateError::Internal(format!("invalid DNS message: {}", e)),
    };

    let error = err.error();
    // `domain` folds a MAC mismatch into FORMERR (`ValidationError::BadSig`
    // has no arm in `server_request`, through at least 0.12.2), but the parser
    // already validated the TSIG structure, so FORMERR here can only mean a
    // bad signature — which RFC 8945 §5.3.2 requires reporting as BADSIG.
    let response = if error == TsigRcode::FORMERR {
        build_unsigned_error(&msg, TsigRcode::BADSIG)
    } else {
        err.build_message(&msg, MessageBuilder::new_vec())
            .ok()
            .map(|builder| builder.finish())
    };

    match response {
        Some(response) => UpdateError::TsigFailed {
            msg: format!("TSIG validation failed: {}", error),
            response,
        },
        None => UpdateError::Internal(format!("failed to build TSIG error response ({})", error)),
    }
}

/// Build a NOTAUTH response carrying an unsigned TSIG error record that
/// echoes the request TSIG with an empty MAC (RFC 8945 §5.3.2).
fn build_unsigned_error(msg: &Message<&[u8]>, error: TsigRcode) -> Option<Vec<u8>> {
    let record = msg
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
            record.owner(),
            record.class(),
            record.ttl(),
            Tsig::new(
                record.data().algorithm(),
                record.data().time_signed(),
                record.data().fudge(),
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
