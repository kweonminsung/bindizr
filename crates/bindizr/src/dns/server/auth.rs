//! Authenticate transfers by TSIG or address ACL; TLS requires both (RFC 9103, Section 7.5).
//! The service gates stored zones; this module gates the virtual catalog.

use std::net::IpAddr;

use bindizr_core::{
    dns::{
        message::{
            ExtendedErrorCode, Opcode, OptRcode, QueryMetadata, extract_opcode,
            has_readable_sections,
        },
        tsig::{RequestSignature, TransferSigner, TsigError, request_signature, verify_tsig},
    },
    model::transfer::TransferTransport,
};
use bindizr_service::{authorization::Caller, tsig_key};
use thiserror::Error;

use super::acl;
use crate::dns::{error::DnsError, server::DnsContext};

/// A rejected transfer's cause; encoding and response limits belong to the handler.
#[derive(Debug, Error)]
pub(crate) enum TransferRefusal {
    #[error("{reason}")]
    Dns {
        reason: String,
        rcode: OptRcode,
        /// The reason an EDNS query hears beside the RCODE (RFC 8914).
        ede: Option<ExtendedErrorCode>,
        /// Boxed to keep refusals small.
        signer: Option<Box<TransferSigner>>,
    },
    #[error("{context}: {source}")]
    Failed {
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        signer: Option<Box<TransferSigner>>,
    },
    #[error(transparent)]
    Tsig(#[from] TsigError),
}

impl TransferRefusal {
    /// Return SERVFAIL under the verified key, if any.
    pub(crate) fn failed(
        context: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
        signer: Option<TransferSigner>,
    ) -> Self {
        Self::Failed {
            context,
            source: Box::new(source),
            signer: signer.map(Box::new),
        }
    }

    /// Identify authentication or backend processing failures for transfer metrics.
    pub(crate) fn is_failure(&self) -> bool {
        match self {
            Self::Dns { rcode, .. } => *rcode == OptRcode::SERVFAIL,
            Self::Failed { .. } => true,
            Self::Tsig(TsigError::Rejected { .. } | TsigError::Malformed(_)) => false,
            Self::Tsig(_) => true,
        }
    }

    /// A refusal by policy: REFUSED, prohibited.
    pub(crate) fn refused(reason: String, signer: Option<TransferSigner>) -> Self {
        Self::Dns {
            reason,
            rcode: OptRcode::REFUSED,
            ede: Some(ExtendedErrorCode::PROHIBITED),
            signer: signer.map(Box::new),
        }
    }

    /// Refuse an unserved zone with NOTAUTH.
    pub(crate) fn not_auth(reason: String, signer: Option<TransferSigner>) -> Self {
        Self::Dns {
            reason,
            rcode: OptRcode::NOTAUTH,
            ede: Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
            signer: signer.map(Box::new),
        }
    }

    /// A request whose TSIG breaks RFC 8945, Section 5.2: FORMERR, unsigned.
    fn malformed(reason: String) -> Self {
        Self::Dns {
            reason,
            rcode: OptRcode::FORMERR,
            ede: None,
            signer: None,
        }
    }

    /// Encode a refusal under the request's response budget, after authentication.
    pub(crate) fn into_response(
        self,
        query_data: &[u8],
        metadata: &QueryMetadata,
    ) -> Result<Vec<u8>, DnsError> {
        match self {
            Self::Dns {
                rcode,
                ede,
                mut signer,
                ..
            } => Ok(metadata.build_signed_error_response(rcode, ede, signer.as_deref_mut())?),
            Self::Failed { mut signer, .. } => Ok(metadata.build_signed_error_response(
                OptRcode::SERVFAIL,
                None,
                signer.as_deref_mut(),
            )?),
            Self::Tsig(TsigError::Rejected { rcode, key, time }) => {
                Ok(bindizr_core::dns::tsig::build_error_response(
                    query_data,
                    key.as_deref(),
                    rcode,
                    time,
                    metadata.response_limit(),
                )?)
            }
            Self::Tsig(TsigError::Malformed(_)) => {
                Ok(metadata.build_signed_error_response(OptRcode::FORMERR, None, None)?)
            }
            Self::Tsig(_) => {
                Ok(metadata.build_signed_error_response(OptRcode::SERVFAIL, None, None)?)
            }
        }
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
        .map_err(|e| TransferRefusal::failed("failed to load TSIG key", e, None))?;
    let Some(tsig_key) = tsig_key else {
        // Verify unknown keys too, so the response encoder receives BADKEY.
        verify_tsig(query_data, None)?;
        return Err(TransferRefusal::refused(
            "TSIG verification passed without a key".to_string(),
            None,
        ));
    };
    let signing_key = tsig_key.to_signing_key().map_err(TransferRefusal::from)?;
    let signer = verify_tsig(query_data, Some(signing_key))?;
    let caller = match Caller::authenticate_tsig_key(dns_cx.daemon(), &tsig_key).await {
        Ok(caller) => caller,
        Err(e) => {
            return Err(TransferRefusal::failed(
                "failed to load the key's grants",
                e,
                Some(signer.into()),
            ));
        }
    };
    Ok(Some(TransferIdentity {
        caller,
        signer: Some(signer.into()),
    }))
}

/// Authenticate TSIG or admit an unsigned address; TLS requires both (RFC 9103, Section 7.5).
/// Content grants are checked when loading the zone or catalog.
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
        return match acl::evaluate_client_access(dns_cx, client_ip).await {
            Ok(true) => Ok(TransferIdentity {
                caller: Caller::unsigned_dns(),
                signer: None,
            }),
            Ok(false) => Err(TransferRefusal::refused(
                format!("IP {} is not an enabled secondary", client_ip),
                None,
            )),
            Err(e) => Err(TransferRefusal::failed(
                "failed to load secondaries",
                e,
                None,
            )),
        };
    };

    // The key answers for the address check, so the refusal is signed too.
    if over_tls {
        match acl::evaluate_client_access(dns_cx, client_ip).await {
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
                return Err(TransferRefusal::failed(
                    "failed to load secondaries",
                    e,
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
    metadata: &QueryMetadata,
    query_data: &[u8],
    rcode: OptRcode,
    ede: Option<ExtendedErrorCode>,
) -> Result<Vec<u8>, DnsError> {
    // Unknown opcodes may carry an opaque body; do not interpret it as TSIG.
    if extract_opcode(query_data).is_some_and(|opcode| opcode != Opcode::QUERY)
        && !has_readable_sections(query_data)
    {
        return Ok(metadata.build_signed_error_response(rcode, ede, None)?);
    }
    match authenticate_tsig_key(dns_cx, query_data).await {
        Ok(identity) => {
            let mut signer = identity.and_then(|identity| identity.signer);
            Ok(metadata.build_signed_error_response(rcode, ede, signer.as_mut())?)
        }
        Err(refusal) => match refusal.into_response(query_data, metadata) {
            Err(DnsError::Tsig(error)) => {
                log::warn!("Failed to encode TSIG refusal: {}", error);
                Ok(metadata.build_signed_error_response(OptRcode::SERVFAIL, None, None)?)
            }
            response => response,
        },
    }
}

#[cfg(test)]
mod tests;
