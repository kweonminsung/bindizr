//! Authenticate an UPDATE request and hand its complete sections to the
//! service. Transport policy and response signing stay at this boundary.

use bindizr_core::{
    dns::{
        message::{Edns, OptRcode},
        name::ZoneName,
        nsupdate::parser::UpdateRequest,
        tsig::{ResponseSigner, TsigError},
    },
    model::{transfer::TransferTransport, tsig_key::TsigKey},
};
use bindizr_service::{
    authorization::Caller,
    nsupdate::{self, NsupdateError, Update},
    tsig_key,
};
use thiserror::Error;

use crate::dns::server::DnsContext;

#[derive(Debug, Error)]
pub(crate) enum UpdateError {
    /// A section breaks the shapes RFC 2136, Sections 3.2.1 and 3.4.1 fix.
    #[error("{0}")]
    FormErr(String),
    /// An OPT the server cannot take: a malformed one is FORMERR, a newer
    /// version BADVERS (RFC 6891, Sections 6.1.1 and 6.1.3).
    #[error("unacceptable EDNS: {0}")]
    Edns(OptRcode),
    /// An UPDATE on the TLS listener, which serves transfers alone
    /// (RFC 9103, Section 7.8): REFUSED, Not Supported.
    #[error("{0}")]
    NotSupported(String),
    #[error("{0}")]
    Refused(String),
    /// TSIG validation failed. Carries the complete NOTAUTH wire response,
    /// built during validation because it must echo (or sign against) the
    /// request's TSIG record (RFC 8945, Sections 5.2–5.3).
    #[error("{msg}")]
    TsigFailed { msg: String, response: Vec<u8> },
    #[error("{0}")]
    YxDomain(String),
    #[error("{0}")]
    YxRrset(String),
    #[error("{0}")]
    NxDomain(String),
    #[error("{0}")]
    NxRrset(String),
    #[error("{0}")]
    NotAuth(String),
    #[error("{0}")]
    NotZone(String),
    /// A fault of the server's own, answered SERVFAIL; the failure stays
    /// beneath it.
    #[error("{message}: {source}")]
    Internal {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl From<TsigError> for UpdateError {
    /// Convert a failure into an nsupdate response error.
    fn from(err: TsigError) -> Self {
        match err {
            TsigError::Malformed(_) => UpdateError::Refused(err.to_string()),
            TsigError::Rejected { rcode, response } => UpdateError::TsigFailed {
                msg: format!("TSIG validation failed: {}", rcode),
                response,
            },
            other => UpdateError::Internal {
                message: "TSIG verification failed".to_string(),
                source: Box::new(other),
            },
        }
    }
}

impl From<NsupdateError> for UpdateError {
    /// Convert a failure into an nsupdate response error.
    fn from(err: NsupdateError) -> Self {
        match err {
            NsupdateError::FormErr(msg) => UpdateError::FormErr(msg),
            NsupdateError::Refused(msg) => UpdateError::Refused(msg),
            NsupdateError::YxDomain(msg) => UpdateError::YxDomain(msg),
            NsupdateError::YxRrset(msg) => UpdateError::YxRrset(msg),
            NsupdateError::NxDomain(msg) => UpdateError::NxDomain(msg),
            NsupdateError::NxRrset(msg) => UpdateError::NxRrset(msg),
            NsupdateError::NotAuth(msg) => UpdateError::NotAuth(msg),
            NsupdateError::NotZone(msg) => UpdateError::NotZone(msg),
            NsupdateError::Internal(err) => UpdateError::Internal {
                message: "failed to apply the update".to_string(),
                source: Box::new(err),
            },
        }
    }
}

/// Apply an UPDATE request, returning whether zone data actually changed. The
/// returned signer is `Some` once the request's TSIG was validated, so the
/// response — success or failure — can be signed.
pub(crate) async fn apply_update(
    dns_cx: &DnsContext,
    request: UpdateRequest,
    query_data: &[u8],
    transport: TransferTransport,
) -> (Result<bool, UpdateError>, Option<ResponseSigner>) {
    let mut signer = None;
    let result = async {
        // A signature is verified first, whatever the listener's answer:
        // keys are zone-independent, and every refusal below is then signed.
        let tsig_key = match &request.tsig {
            Some(tsig) => {
                let (tsig_key, verified) =
                    authenticate_tsig_key(dns_cx, &tsig.name, query_data).await?;
                signer = Some(verified);
                tsig_key
            }
            None => None,
        };

        // RFC 9103, Section 7.8: the TLS listener serves transfers alone.
        if transport == TransferTransport::Tls {
            return Err(UpdateError::NotSupported(
                "UPDATE is not served over TLS".to_string(),
            ));
        }

        // An unsigned update carries no identity, so admitting one admits
        // every client that reaches the listener — the same trade
        // `api.authentication_required = false` makes for the API.
        let caller = match tsig_key {
            Some(tsig_key) => Caller::authenticate_tsig_key(dns_cx.daemon(), &tsig_key)
                .await
                .map_err(NsupdateError::from)?,
            None if dns_cx.daemon().config().dns.nsupdate.tsig_required => {
                return Err(UpdateError::Refused(
                    "unsigned NSUPDATE refused: no TSIG record present".to_string(),
                ));
            }
            None => Caller::unsigned_dns(),
        };

        // An OPT the server cannot take is answered before the update is read.
        match request.edns {
            Edns::Absent | Edns::Present { .. } => {}
            Edns::Malformed => return Err(UpdateError::Edns(OptRcode::FORMERR)),
            Edns::UnsupportedVersion(_) => return Err(UpdateError::Edns(OptRcode::BADVERS)),
        }

        // The parser renders the zone absolute; decoding it into labels here
        // leaves no string test to decide where its root dot ends the name. A
        // name no zone can carry is not served here (RFC 2136, Section 3.1.2).
        if request.zone_name == "." {
            return Err(UpdateError::NotAuth(
                "the root zone is not served here".to_string(),
            ));
        }
        let zone_name = ZoneName::parse(&request.zone_name).map_err(|e| {
            UpdateError::NotAuth(format!("'{}' is not a zone name: {}", request.zone_name, e))
        })?;

        let update = Update {
            zone_name,
            zone_class: request.zone_class,
            prerequisites: &request.prerequisites,
            updates: &request.updates,
            message: query_data,
        };

        let changed = nsupdate::apply(dns_cx.daemon(), &caller, update).await?;
        Ok(changed)
    }
    .await;
    (result, signer)
}

/// Authenticate the request by the key `key_name` names: its TSIG verified,
/// the key comes back with the context that signs the response.
pub(crate) async fn authenticate_tsig_key(
    dns_cx: &DnsContext,
    key_name: &str,
    query_data: &[u8],
) -> Result<(Option<TsigKey>, ResponseSigner), UpdateError> {
    let tsig_key = tsig_key::find_by_wire_name(dns_cx.daemon(), key_name)
        .await
        .map_err(|e| UpdateError::Internal {
            message: "failed to load TSIG key".to_string(),
            source: Box::new(e),
        })?;

    // An unknown key still runs validation: the empty key store makes it
    // produce the BADKEY error response.
    let domain_key = tsig_key.as_ref().map(TsigKey::to_domain_key).transpose()?;
    let signer = bindizr_core::dns::tsig::verify_tsig(query_data, domain_key)?;
    Ok((tsig_key, signer))
}
