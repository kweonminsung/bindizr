//! Who may transfer a zone: the key that signed the request, or — when it
//! carried no TSIG — the address ACL a deployment with no keys keeps using.
//! A real zone's grant is decided in the service beside the row it serves;
//! the virtual catalog zone, which holds no grants, is gated here.

use std::net::IpAddr;

use bindizr_core::{
    config::bindizr_config,
    dns::{
        message::{ParsedQuery, Rcode},
        tsig::{
            RequestSignature, TransferSigner, TsigError, request_signature, verify_tsig_sequence,
        },
    },
    model::tsig_key::TsigKey,
};
use bindizr_service::tsig_key::TsigKeyService;

use super::acl;
use crate::dns::error::XfrError;

/// The error response a request is owed, signed when a key was accepted: once
/// a key is in play the answer carries it, error or not (RFC 8945, Section 5.3).
pub(crate) fn signed_error(
    query: &ParsedQuery,
    rcode: Rcode,
    signer: Option<&mut TransferSigner>,
) -> Result<Vec<u8>, XfrError> {
    match signer {
        Some(signer) => query
            .signed_error_response(rcode, signer)
            .map_err(XfrError::ProtocolError),
        None => Ok(query.error_response(rcode)),
    }
}

/// A refused transfer and the response it owes the client: a TSIG failure
/// answers with its own error RR, anything else with REFUSED, signed by the
/// key that got that far.
pub(crate) struct TransferRefusal {
    pub(crate) reason: String,
    response: Option<Vec<u8>>,
    signer: Option<TransferSigner>,
}

impl TransferRefusal {
    /// Build a transfer refusal with the supplied reason.
    pub(crate) fn refused(reason: String, signer: Option<TransferSigner>) -> Self {
        TransferRefusal {
            reason,
            response: None,
            signer,
        }
    }

    /// Convert the refusal into a DNS response.
    pub(crate) fn into_response(mut self, query: &ParsedQuery) -> Result<Vec<u8>, XfrError> {
        if let Some(response) = self.response {
            return Ok(response);
        }
        signed_error(query, Rcode::REFUSED, self.signer.as_mut())
    }
}

/// Who a transfer request is: the verified key that signed it, or nobody when
/// the address ACL admitted it unsigned; the signer answers under that key.
pub(crate) struct TransferIdentity {
    pub(crate) key: Option<TsigKey>,
    pub(crate) signer: Option<TransferSigner>,
}

/// Authenticate a transfer request: verify its TSIG under the key it names, or
/// admit an unsigned one by the address ACL. The catalog zone is virtual and
/// holds no grants, so only the ACL or a global key reaches it.
pub(crate) async fn authenticate_transfer(
    query_data: &[u8],
    client_ip: IpAddr,
    zone_name: &str,
) -> Result<TransferIdentity, TransferRefusal> {
    let key_name = match request_signature(query_data) {
        RequestSignature::Key(key_name) => key_name,
        RequestSignature::Absent => {
            return match acl::is_client_allowed(client_ip).await {
                Ok(true) => Ok(TransferIdentity {
                    key: None,
                    signer: None,
                }),
                Ok(false) => Err(TransferRefusal::refused(
                    format!("IP {} is not an enabled secondary", client_ip),
                    None,
                )),
                Err(e) => Err(TransferRefusal::refused(
                    format!("failed to load secondaries: {}", e),
                    None,
                )),
            };
        }
        // The address would have allowed this one; a TSIG that does not parse
        // must not be answered as though none had been sent.
        RequestSignature::Malformed => {
            return Err(TransferRefusal::refused(
                "TSIG record is malformed".to_string(),
                None,
            ));
        }
    };

    // An unknown key still runs validation: the empty key store makes it
    // produce the BADKEY error response.
    let key = TsigKeyService::find_by_wire_name(&key_name)
        .await
        .map_err(|e| TransferRefusal::refused(format!("failed to load TSIG key: {}", e), None))?;
    let domain_key = key
        .as_ref()
        .map(TsigKey::to_domain_key)
        .transpose()
        .map_err(TransferRefusal::from)?;
    let signer = verify_tsig_sequence(query_data, domain_key).map_err(TransferRefusal::from)?;

    let key = key.expect("verification succeeded, so the key is known");
    if bindizr_config().dns.is_catalog_zone(zone_name) && !key.is_global {
        return Err(TransferRefusal::refused(
            format!(
                "TSIG key '{}' is not granted zone '{}' whole",
                key.name, zone_name
            ),
            Some(signer),
        ));
    }
    Ok(TransferIdentity {
        key: Some(key),
        signer: Some(signer),
    })
}

impl From<TsigError> for TransferRefusal {
    /// Translate a TSIG error into a transfer refusal with its required response.
    fn from(error: TsigError) -> Self {
        match error {
            TsigError::Failed { message, response } => TransferRefusal {
                reason: message,
                response: Some(response),
                signer: None,
            },
            TsigError::Malformed(message) | TsigError::Internal(message) => {
                TransferRefusal::refused(message, None)
            }
        }
    }
}
