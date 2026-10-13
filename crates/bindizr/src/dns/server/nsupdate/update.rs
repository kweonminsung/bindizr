//! Authenticate an UPDATE request and hand its complete sections to the
//! service. Transport policy and response signing stay at this boundary.

use bindizr_core::{
    dns::{
        message::OptRcode,
        name::{ParseNameError, ZoneName},
        nsupdate::parser::UpdateRequest,
        tsig::{ResponseSigner, TsigError},
    },
    model::{transfer::TransferTransport, tsig_key::TsigKey},
};
use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    nsupdate::{self, NsupdateError, Update},
    tsig_key,
};
use thiserror::Error;

use crate::dns::server::DnsContext;

#[derive(Debug, Error)]
pub(crate) enum UpdateError {
    /// Malformed OPT or unsupported EDNS version (RFC 6891, Section 6.1).
    #[error("unacceptable EDNS: {0}")]
    Edns(OptRcode),
    #[error("{0}")]
    NotSupported(String),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    NotAuth(String),
    #[error("'{name}' is not a zone name: {source}")]
    ZoneName {
        name: String,
        #[source]
        source: ParseNameError,
    },
    #[error("{0}")]
    Tsig(#[from] TsigError),
    #[error("{0}")]
    Nsupdate(#[from] NsupdateError),
    #[error("failed to load TSIG key: {0}")]
    LoadTsigKey(#[source] ServiceError),
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
        if let Some(rcode) = request.edns.format_error() {
            return Err(UpdateError::Edns(rcode));
        }

        // The parser renders the zone absolute; decoding it into labels here
        // leaves no string test to decide where its root dot ends the name. A
        // name no zone can carry is not served here (RFC 2136, Section 3.1.2).
        if request.zone_name == "." {
            return Err(UpdateError::NotAuth(
                "the root zone is not served here".to_string(),
            ));
        }
        let zone_name =
            ZoneName::parse(&request.zone_name).map_err(|source| UpdateError::ZoneName {
                name: request.zone_name.clone(),
                source,
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
        .map_err(UpdateError::LoadTsigKey)?;

    // An unknown key still runs validation: the empty key store makes it
    // produce the BADKEY error response.
    let signing_key = tsig_key.as_ref().map(TsigKey::to_signing_key).transpose()?;
    let signer = bindizr_core::dns::tsig::verify_tsig(query_data, signing_key)?;
    Ok((tsig_key, signer))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use bindizr_core::dns::{message::Rcode, nsupdate::parser::UpdateShapeError};

    use super::*;

    /// Preserve the complete parser and backend source chains through the DNS boundary.
    #[test]
    fn update_errors_retain_sources_across_layers() {
        let err = UpdateError::from(NsupdateError::from(UpdateShapeError::NonzeroTtl));
        let nsupdate = err
            .source()
            .unwrap()
            .downcast_ref::<NsupdateError>()
            .unwrap();
        assert_eq!(nsupdate.rcode(), Rcode::FORMERR);
        assert_eq!(
            nsupdate
                .source()
                .unwrap()
                .downcast_ref::<UpdateShapeError>(),
            Some(&UpdateShapeError::NonzeroTtl)
        );

        let err = UpdateError::from(NsupdateError::from(ServiceError::internal_with_source(
            "storage failed",
            std::io::Error::other("storage"),
        )));
        let nsupdate = err
            .source()
            .unwrap()
            .downcast_ref::<NsupdateError>()
            .unwrap();
        assert_eq!(nsupdate.rcode(), Rcode::SERVFAIL);
        let service = nsupdate
            .source()
            .unwrap()
            .downcast_ref::<ServiceError>()
            .unwrap();
        assert!(service.source().unwrap().is::<std::io::Error>());

        let err = UpdateError::from(TsigError::EmptySecret);
        assert!(matches!(
            err.source().unwrap().downcast_ref::<TsigError>(),
            Some(TsigError::EmptySecret)
        ));
    }
}
