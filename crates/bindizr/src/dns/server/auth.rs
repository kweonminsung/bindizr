//! Who may transfer a zone: the key that signed the request, or — when it
//! carried no TSIG — the address ACL a deployment with no keys keeps using.
//! A real zone's grant is decided in the service beside the row it serves;
//! the virtual catalog zone, which has no row, is gated here.

use std::net::IpAddr;

use bindizr_core::{
    dns::{
        message::{ParsedQuery, Rcode},
        tsig::{
            RequestSignature, TransferSigner, TsigError, request_signature, verify_tsig_sequence,
        },
    },
    model::tsig_key::TsigKey,
};
use bindizr_service::tsig_key;

use super::acl;
use crate::dns::{error::XfrError, server::DnsContext};

/// A refused transfer and the response it owes the client: a TSIG failure
/// answers with its own error record, anything else with REFUSED, signed by the
/// key that got that far.
#[derive(Debug)]
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
        Ok(query.signed_error_response(Rcode::REFUSED, self.signer.as_mut())?)
    }
}

/// Who a transfer request is: the verified key that signed it, or nobody when
/// the address ACL admitted it unsigned; the signer answers under that key.
#[derive(Debug, Clone)]
pub(crate) struct TransferIdentity {
    pub(crate) key: Option<TsigKey>,
    pub(crate) signer: Option<TransferSigner>,
}

/// Authenticate a transfer request: verify its TSIG under the key it names, or
/// admit an unsigned one by the address ACL. What the key may read is decided
/// where the content is loaded, the catalog's included.
pub(crate) async fn authenticate_transfer(
    dns_cx: &DnsContext,
    query_data: &[u8],
    client_ip: IpAddr,
) -> Result<TransferIdentity, TransferRefusal> {
    let cx = dns_cx.daemon();
    let key_name = match request_signature(query_data) {
        RequestSignature::Key(key_name) => key_name,
        RequestSignature::Absent => {
            // An address is no credential the content transaction re-reads:
            // removing a secondary refuses later transfers, not one admitted.
            return match acl::is_client_allowed(dns_cx, client_ip).await {
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

    let key = tsig_key::find_by_wire_name(cx, &key_name)
        .await
        .map_err(|e| TransferRefusal::refused(format!("failed to load TSIG key: {}", e), None))?;
    let Some(key) = key else {
        // An unknown key still runs validation: the empty key store makes it
        // produce the BADKEY error response.
        verify_tsig_sequence(query_data, None).map_err(TransferRefusal::from)?;
        return Err(TransferRefusal::refused(
            "TSIG verification passed without a key".to_string(),
            None,
        ));
    };
    let domain_key = key.to_domain_key().map_err(TransferRefusal::from)?;
    let signer =
        verify_tsig_sequence(query_data, Some(domain_key)).map_err(TransferRefusal::from)?;

    Ok(TransferIdentity {
        key: Some(key),
        signer: Some(signer),
    })
}

impl From<TsigError> for TransferRefusal {
    /// Translate a TSIG error into a transfer refusal with its required response.
    fn from(error: TsigError) -> Self {
        match error {
            TsigError::Rejected { rcode, response } => TransferRefusal {
                reason: format!("TSIG validation failed: {}", rcode),
                response: Some(response),
                signer: None,
            },
            other => TransferRefusal::refused(other.to_string(), None),
        }
    }
}
