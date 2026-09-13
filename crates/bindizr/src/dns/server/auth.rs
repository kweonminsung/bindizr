//! Who may transfer a zone: the key that signed the request, or — when it
//! carried no TSIG — the address ACL a deployment with no keys keeps using.

use std::net::IpAddr;

use bindizr_core::dns::{
    message::{ParsedQuery, Rcode},
    tsig::{TransferSigner, TsigError, signed_key_name, to_domain_key, verify_tsig_sequence},
};
use bindizr_service::tsig_key::{TsigKeyService, grant::TsigGrantService};

use super::acl;
use crate::dns::error::XfrError;

/// A refused transfer and the response it owes the client: a TSIG failure
/// answers with its own error RR, anything else with REFUSED, signed by the
/// key that got that far.
pub(crate) struct TransferRefusal {
    pub(crate) reason: String,
    response: Option<Vec<u8>>,
    signer: Option<TransferSigner>,
}

impl TransferRefusal {
    fn refused(reason: String, signer: Option<TransferSigner>) -> Self {
        TransferRefusal {
            reason,
            response: None,
            signer,
        }
    }

    pub(crate) fn into_response(mut self, query: &ParsedQuery) -> Result<Vec<u8>, XfrError> {
        if let Some(response) = self.response {
            return Ok(response);
        }
        match self.signer.as_mut() {
            Some(signer) => query
                .signed_error_response(Rcode::REFUSED, signer)
                .map_err(XfrError::ProtocolError),
            None => Ok(query.error_response(Rcode::REFUSED)),
        }
    }
}

/// Decide whether the request may transfer the zone, and under which key. A
/// signed request is authorized by that key and answered under it; an unsigned
/// one by the address ACL.
pub(crate) async fn authorize_transfer(
    query_data: &[u8],
    client_ip: IpAddr,
    zone_name: &str,
) -> Result<Option<TransferSigner>, TransferRefusal> {
    let Some(key_name) = signed_key_name(query_data) else {
        return match acl::is_client_allowed(client_ip).await {
            true => Ok(None),
            false => Err(TransferRefusal::refused(
                format!("IP {} is not a configured secondary", client_ip),
                None,
            )),
        };
    };

    // An unknown key still runs validation: the empty key store makes it
    // produce the BADKEY error response.
    let key = TsigKeyService::find_by_wire_name(&key_name)
        .await
        .map_err(|e| TransferRefusal::refused(format!("failed to load TSIG key: {}", e), None))?;
    let domain_key = key
        .as_ref()
        .map(to_domain_key)
        .transpose()
        .map_err(to_refusal)?;
    let signer = verify_tsig_sequence(query_data, domain_key).map_err(to_refusal)?;

    let key = key.expect("verification succeeded, so the key is known");
    match TsigGrantService::authorize_transfer(&key, zone_name).await {
        Ok(true) => Ok(Some(signer)),
        Ok(false) => Err(TransferRefusal::refused(
            format!(
                "TSIG key '{}' is not granted zone '{}' whole",
                key.name, zone_name
            ),
            Some(signer),
        )),
        Err(e) => Err(TransferRefusal::refused(
            format!("failed to authorize TSIG key '{}': {}", key.name, e),
            Some(signer),
        )),
    }
}

fn to_refusal(error: TsigError) -> TransferRefusal {
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
