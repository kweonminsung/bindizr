//! Who may transfer a zone: the key that signed the request, or — when it
//! carried no TSIG — the address ACL a deployment with no keys keeps using.
//! Over TLS the two are required together (RFC 9103, Section 7.5). A real
//! zone's grant is decided in the service beside the row it serves; the
//! virtual catalog zone, which has no row, is gated here.

use std::net::IpAddr;

use bindizr_core::{
    dns::{
        message::{ExtendedErrorCode, OptRcode, ParsedQuery},
        tsig::{
            RequestSignature, TransferSigner, TsigError, request_signature, verify_tsig_sequence,
        },
    },
    model::transfer::TransferTransport,
};
use bindizr_service::{authorization::Caller, tsig_key};

use super::acl;
use crate::dns::{error::XfrError, server::DnsContext};

/// A refused transfer and the response it owes the client: a TSIG failure
/// its own error record, a malformed TSIG an unsigned FORMERR (RFC 8945,
/// Section 5.2), anything else REFUSED under the key that got that far.
#[derive(Debug, Clone)]
pub(crate) struct TransferRefusal {
    pub(crate) reason: String,
    rcode: OptRcode,
    /// The reason an EDNS query hears beside the RCODE (RFC 8914).
    ede: Option<ExtendedErrorCode>,
    response: Option<Vec<u8>>,
    /// Boxed so a refusal travels as a small `Err`.
    signer: Option<Box<TransferSigner>>,
}

impl TransferRefusal {
    /// A refusal by policy: REFUSED, prohibited.
    pub(crate) fn refused(reason: String, signer: Option<TransferSigner>) -> Self {
        TransferRefusal {
            reason,
            rcode: OptRcode::REFUSED,
            ede: Some(ExtendedErrorCode::PROHIBITED),
            response: None,
            signer: signer.map(Box::new),
        }
    }

    /// A request whose TSIG breaks RFC 8945, Section 5.2: FORMERR, unsigned.
    fn malformed(reason: String) -> Self {
        TransferRefusal {
            reason,
            rcode: OptRcode::FORMERR,
            ede: None,
            response: None,
            signer: None,
        }
    }

    /// Convert the refusal into a DNS response.
    pub(crate) fn into_response(mut self, query: &ParsedQuery) -> Result<Vec<u8>, XfrError> {
        if let Some(response) = self.response {
            return Ok(response);
        }
        Ok(query.signed_error_response(self.rcode, self.ede, self.signer.as_deref_mut())?)
    }
}

/// Hold an authenticated transfer to `dns.transfer.require_tls` (RFC 9103,
/// Section 11): a plain transport is refused under the key that signed it.
pub(crate) fn authorize_transport(
    dns_cx: &DnsContext,
    transport: TransferTransport,
    identity: TransferIdentity,
) -> Result<TransferIdentity, TransferRefusal> {
    if dns_cx.daemon().config().dns.transfer.require_tls && transport != TransferTransport::Tls {
        return Err(TransferRefusal::refused(
            "transfers require TLS (dns.transfer.require_tls)".to_string(),
            identity.signer,
        ));
    }
    Ok(identity)
}

/// Who a transfer request is: the caller its key became, or the unsigned DNS
/// caller the address ACL admitted; the signer answers under that key.
#[derive(Debug, Clone)]
pub(crate) struct TransferIdentity {
    pub(crate) caller: Caller,
    pub(crate) signer: Option<TransferSigner>,
}

/// Verify the key a request names, for an answer that needs no address:
/// `None` for an unsigned request, the refusal a bad or malformed TSIG earns.
pub(crate) async fn authenticate_tsig_key(
    dns_cx: &DnsContext,
    query_data: &[u8],
) -> Result<Option<TransferIdentity>, TransferRefusal> {
    let key_name = match request_signature(query_data) {
        RequestSignature::Key { name, .. } => name,
        RequestSignature::Absent => return Ok(None),
        // The address would have allowed this one; a TSIG that does not parse
        // must not be answered as though none had been sent.
        RequestSignature::Malformed => {
            return Err(TransferRefusal::malformed(
                "TSIG record is malformed (RFC 8945, Section 5.2)".to_string(),
            ));
        }
    };

    let tsig_key = tsig_key::find_by_wire_name(dns_cx.daemon(), &key_name)
        .await
        .map_err(|e| TransferRefusal::refused(format!("failed to load TSIG key: {}", e), None))?;
    let Some(tsig_key) = tsig_key else {
        // An unknown key still runs validation: the empty key store makes it
        // produce the BADKEY error response.
        verify_tsig_sequence(query_data, None).map_err(TransferRefusal::from)?;
        return Err(TransferRefusal::refused(
            "TSIG verification passed without a key".to_string(),
            None,
        ));
    };
    let domain_key = tsig_key.to_domain_key().map_err(TransferRefusal::from)?;
    let signer =
        verify_tsig_sequence(query_data, Some(domain_key)).map_err(TransferRefusal::from)?;
    let caller = Caller::authenticate_tsig_key(dns_cx.daemon(), &tsig_key)
        .await
        .map_err(|e| {
            TransferRefusal::refused(format!("failed to load the key's grants: {}", e), None)
        })?;
    Ok(Some(TransferIdentity {
        caller,
        signer: Some(signer),
    }))
}

/// Authenticate a transfer request: verify its TSIG under the key it names, or
/// admit an unsigned one by the address ACL; over TLS both must pass (RFC
/// 9103, Section 7.5). What the key may read is decided where the content is
/// loaded, the catalog's included.
pub(crate) async fn authenticate_transfer(
    dns_cx: &DnsContext,
    query_data: &[u8],
    client_ip: IpAddr,
    transport: TransferTransport,
) -> Result<TransferIdentity, TransferRefusal> {
    let over_tls = matches!(transport, TransferTransport::Tls);
    let Some(identity) = authenticate_tsig_key(dns_cx, query_data).await? else {
        if over_tls {
            return Err(TransferRefusal::refused(
                "an XoT request must be TSIG-signed (RFC 9103, Section 7.5)".to_string(),
                None,
            ));
        }
        // An address is no credential the content transaction re-reads:
        // removing a secondary refuses later transfers, not one admitted.
        return match acl::is_client_allowed(dns_cx, client_ip).await {
            Ok(true) => Ok(TransferIdentity {
                caller: Caller::unsigned_dns(),
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
    };

    // The key answers for the address check, so the refusal is signed too.
    if over_tls {
        match acl::is_client_allowed(dns_cx, client_ip).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(TransferRefusal::refused(
                    format!(
                        "IP {} is not an enabled secondary; XoT needs the key and the address (RFC 9103, Section 7.5)",
                        client_ip
                    ),
                    identity.signer,
                ));
            }
            Err(e) => {
                return Err(TransferRefusal::refused(
                    format!("failed to load secondaries: {}", e),
                    identity.signer,
                ));
            }
        }
    }

    Ok(identity)
}

/// Answer a query refused before any handler: under its key when it has one
/// (RFC 8945, Section 5.3), or with the TSIG error a bad key earns instead.
pub(crate) async fn refuse_query(
    dns_cx: &DnsContext,
    query: &ParsedQuery,
    query_data: &[u8],
    rcode: OptRcode,
    ede: Option<ExtendedErrorCode>,
) -> Result<Vec<u8>, XfrError> {
    match authenticate_tsig_key(dns_cx, query_data).await {
        Ok(identity) => {
            let mut signer = identity.and_then(|identity| identity.signer);
            Ok(query.signed_error_response(rcode, ede, signer.as_mut())?)
        }
        Err(refusal) => refusal.into_response(query),
    }
}

impl From<TsigError> for TransferRefusal {
    /// Translate a TSIG error into a transfer refusal with its required response.
    fn from(error: TsigError) -> Self {
        match error {
            TsigError::Rejected { rcode, response } => TransferRefusal {
                reason: format!("TSIG validation failed: {}", rcode),
                rcode: OptRcode::NOTAUTH,
                ede: None,
                response: Some(response),
                signer: None,
            },
            other => TransferRefusal::refused(other.to_string(), None),
        }
    }
}
