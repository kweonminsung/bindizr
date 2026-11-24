//! Authenticate DNS requests by TSIG or address ACL; XoT requires both (RFC 9103, Section 7.5).
//! The service decides zone and catalog grants when it loads what a transfer serves.

use std::net::IpAddr;

use bindizr_core::dns::message::{ExtendedErrorCode, Opcode, OptRcode, QueryMetadata};
use bindizr_core::dns::tsig::{
    RequestSignature, RequestTsig, ResponseSigner, TransferSigner, TsigError,
};
use bindizr_core::dns::{message, tsig};
use bindizr_core::model::transfer::TransferTransport;
use bindizr_core::model::tsig_key::TsigKey;
use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::transfer::TransferLogErrorCode;
use bindizr_service::tsig_key;
use thiserror::Error;

use crate::dns::error::DnsError;
use crate::dns::server::{DnsContext, acl};

/// Why a DNS query was rejected, with its status and any signing context.
#[derive(Debug, Error)]
pub(crate) enum QueryRefusal {
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

impl QueryRefusal {
    /// Return a fixed log classification without the detailed refusal or its cause.
    pub(crate) fn to_log_code(&self) -> TransferLogErrorCode {
        match self {
            Self::Dns { rcode, .. } => TransferLogErrorCode::Dns(*rcode),
            Self::Failed { .. } => TransferLogErrorCode::Dns(OptRcode::SERVFAIL),
            Self::Tsig(TsigError::Rejected { rcode, .. }) => TransferLogErrorCode::Tsig(*rcode),
            Self::Tsig(_) => TransferLogErrorCode::TsigAuthenticationFailed,
        }
    }

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

    /// Return whether this is an authentication or backend processing failure.
    pub(crate) fn is_failure(&self) -> bool {
        match self {
            Self::Dns { rcode, .. } => *rcode == OptRcode::SERVFAIL,
            Self::Failed { .. } => true,
            Self::Tsig(TsigError::Rejected { .. }) => false,
            Self::Tsig(_) => true,
        }
    }

    /// Refuse by policy: REFUSED, prohibited.
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

    /// Refuse a request whose TSIG breaks RFC 8945, Section 5.2: FORMERR,
    /// unsigned.
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
        metadata: &QueryMetadata,
        query_data: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        match self {
            Self::Dns {
                rcode,
                ede,
                mut signer,
                ..
            } => Ok(metadata.build_signed_error_response(rcode, ede, signer.as_deref_mut())?),
            Self::Failed {
                context,
                source,
                mut signer,
            } => {
                // A backend failure leaves the process here as SERVFAIL, so its cause is logged.
                log::error!("DNS request failed with a server fault: {context}: {source:?}");

                Ok(metadata.build_signed_error_response(
                    OptRcode::SERVFAIL,
                    None,
                    signer.as_deref_mut(),
                )?)
            }
            Self::Tsig(TsigError::Rejected { rcode, key, time }) => Ok(tsig::build_error_response(
                query_data,
                key.as_deref(),
                rcode,
                time,
                metadata.response_limit(),
            )?),
            // A stored key that will not decode leaves the process here as SERVFAIL.
            Self::Tsig(error) => {
                log::error!("DNS request failed with a server fault: {error:?}");

                Ok(metadata.build_signed_error_response(OptRcode::SERVFAIL, None, None)?)
            }
        }
    }
}

/// Authenticate and enforce the transfer-only transport policy (RFC 9103,
/// Section 11). A refused plain request is answered under the verified key.
pub(crate) async fn admit_transfer(
    dns_cx: &DnsContext,
    client_ip: IpAddr,
    query_data: &[u8],
    transport: TransferTransport,
) -> Result<QueryIdentity, QueryRefusal> {
    let identity = authenticate_query(dns_cx, client_ip, query_data, transport).await?;

    if dns_cx.daemon().config().dns.transfer.require_tls && transport != TransferTransport::Tls {
        return Err(QueryRefusal::refused(
            "transfers require TLS (dns.transfer.require_tls)".to_string(),
            identity.signer,
        ));
    }

    Ok(identity)
}

/// Who sent a query: the caller its key became, or the unsigned DNS
/// caller the address ACL admitted; the signer answers under that key.
#[derive(Debug, Clone)]
pub(crate) struct QueryIdentity {
    pub(crate) caller: Caller,
    pub(crate) signer: Option<TransferSigner>,
}

/// Why a request's TSIG key could not be loaded or its signature verified.
#[derive(Debug, Error)]
pub(crate) enum VerifyRequestTsigError {
    #[error("failed to load TSIG key: {0}")]
    LoadKey(#[source] ServiceError),
    #[error(transparent)]
    Tsig(#[from] TsigError),
}

/// Verify a request's named key and return it with its response signer.
pub(crate) async fn verify_request_tsig(
    dns_cx: &DnsContext,
    query_data: &[u8],
    key_name: &str,
) -> Result<(TsigKey, ResponseSigner), VerifyRequestTsigError> {
    let tsig_key = tsig_key::find_by_wire_name(dns_cx.daemon(), key_name)
        .await
        .map_err(VerifyRequestTsigError::LoadKey)?;
    let Some(tsig_key) = tsig_key else {
        // An unknown key is answered BADKEY, signed by nothing (RFC 8945, Section 5.2).
        return Err(tsig::reject_unknown_key(query_data).into());
    };
    let signer = tsig::verify_tsig(query_data, tsig_key.to_signing_key()?)?;

    Ok((tsig_key, signer))
}

impl From<VerifyRequestTsigError> for QueryRefusal {
    /// Keep key lookup and TSIG protocol failures distinct.
    fn from(error: VerifyRequestTsigError) -> Self {
        match error {
            VerifyRequestTsigError::LoadKey(source) => {
                Self::failed("failed to load TSIG key", source, None)
            }
            VerifyRequestTsigError::Tsig(error) => Self::Tsig(error),
        }
    }
}

/// Authenticate a signed query's key and load its grants, independent of address.
/// An unsigned query has no key identity.
async fn authenticate_query_tsig(
    dns_cx: &DnsContext,
    query_data: &[u8],
) -> Result<Option<QueryIdentity>, QueryRefusal> {
    let key_name = match tsig::request_signature(query_data) {
        RequestSignature::Key(RequestTsig { name, .. }) => name,
        RequestSignature::Absent => return Ok(None),
        // The address would have allowed this one; a TSIG that does not parse
        // must not be answered as though none had been sent.
        RequestSignature::Malformed => {
            return Err(QueryRefusal::malformed(
                "TSIG record is malformed (RFC 8945, Section 5.2)".to_string(),
            ));
        }
    };

    let cx = dns_cx.daemon();
    let (tsig_key, signer) = verify_request_tsig(dns_cx, query_data, &key_name).await?;

    let caller = match Caller::authenticate_tsig_key(cx, &tsig_key).await {
        Ok(caller) => caller,
        Err(error) => {
            return Err(QueryRefusal::failed(
                "failed to load the key's grants",
                error,
                Some(signer.into()),
            ));
        }
    };

    Ok(Some(QueryIdentity {
        caller,
        signer: Some(signer.into()),
    }))
}

/// Authenticate TSIG or admit an unsigned address; TLS requires both (RFC 9103, Section 7.5).
/// Content grants are checked when loading the zone or catalog.
pub(crate) async fn authenticate_query(
    dns_cx: &DnsContext,
    client_ip: IpAddr,
    query_data: &[u8],
    transport: TransferTransport,
) -> Result<QueryIdentity, QueryRefusal> {
    let over_tls = transport == TransferTransport::Tls;

    let Some(identity) = authenticate_query_tsig(dns_cx, query_data).await? else {
        if over_tls {
            return Err(QueryRefusal::refused(
                "an XoT request must be TSIG-signed (RFC 9103, Section 7.5)".to_string(),
                None,
            ));
        }

        // An address is no credential the content transaction re-reads:
        // removing a secondary refuses later transfers, not one admitted.
        return match acl::evaluate_client_access(dns_cx, client_ip).await {
            Ok(true) => Ok(QueryIdentity {
                caller: Caller::unsigned_dns(),
                signer: None,
            }),
            Ok(false) => Err(QueryRefusal::refused(
                format!("IP {client_ip} is not an enabled secondary"),
                None,
            )),
            Err(error) => Err(QueryRefusal::failed(
                "failed to load secondaries",
                error,
                None,
            )),
        };
    };

    // The key answers for the address check, so the refusal is signed too.
    if over_tls {
        match acl::evaluate_client_access(dns_cx, client_ip).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(QueryRefusal::refused(
                    format!(
                        "IP {client_ip} is not an enabled secondary; XoT needs the key and the address (RFC 9103, Section 7.5)"
                    ),
                    identity.signer,
                ));
            }
            Err(error) => {
                return Err(QueryRefusal::failed(
                    "failed to load secondaries",
                    error,
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
    if message::extract_opcode(query_data).is_some_and(|opcode| opcode != Opcode::QUERY)
        && !message::has_readable_sections(query_data)
    {
        return Ok(metadata.build_signed_error_response(rcode, ede, None)?);
    }

    match authenticate_query_tsig(dns_cx, query_data).await {
        Ok(identity) => {
            let mut signer = identity.and_then(|identity| identity.signer);
            Ok(metadata.build_signed_error_response(rcode, ede, signer.as_mut())?)
        }
        Err(refusal) => {
            log::warn!("Failed to authenticate the TSIG of a refused request: {refusal}");

            match refusal.into_response(metadata, query_data) {
                Err(DnsError::TsigResponse(error)) => {
                    log::warn!("Failed to encode TSIG refusal: {error}");
                    Ok(metadata.build_signed_error_response(OptRcode::SERVFAIL, None, None)?)
                }
                response => response,
            }
        }
    }
}

#[cfg(test)]
mod tests;
