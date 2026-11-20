//! Authenticate an UPDATE request and hand its complete sections to the
//! service. Response signing stays at this boundary.

use bindizr_core::dns::message::OptRcode;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::dns::nsupdate::parser::UpdateRequest;
use bindizr_core::dns::tsig;
use bindizr_core::dns::tsig::{ResponseSigner, TsigError};
use bindizr_core::model::tsig_key::TsigKey;
use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::nsupdate::{NsupdateError, Update};
use bindizr_service::{nsupdate, tsig_key};
use thiserror::Error;

use crate::dns::server::DnsContext;

/// Why an UPDATE was not applied, classified for the RCODE it answers.
#[derive(Debug, Error)]
pub(crate) enum UpdateError {
    /// Malformed OPT or unsupported EDNS version (RFC 6891, Section 6.1).
    #[error("unacceptable EDNS: {rcode}")]
    Edns { rcode: OptRcode },
    #[error("{reason}")]
    NotAuth { reason: String },
    #[error("{0}")]
    Tsig(#[from] TsigError),
    #[error("{0}")]
    Nsupdate(#[from] NsupdateError),
    #[error("failed to load TSIG key: {0}")]
    LoadTsigKey(#[source] ServiceError),
}

/// Apply UPDATE and report whether data changed, retaining a verified signer
/// for any response and the key it verified for the access log.
pub(crate) async fn apply_update(
    dns_cx: &DnsContext,
    request: UpdateRequest,
    zone_name: Result<ZoneName, ServiceError>,
    query_data: &[u8],
) -> (
    Result<bool, UpdateError>,
    Option<ResponseSigner>,
    Option<TsigKey>,
) {
    let cx = dns_cx.daemon();
    let mut signer = None;
    let mut verified_key = None;

    let result = async {
        // A signature is verified first, whatever the listener's answer:
        // keys are zone-independent, and every refusal below is then signed.
        if let Some(tsig) = &request.tsig {
            let (tsig_key, verified) =
                authenticate_tsig_key(dns_cx, query_data, &tsig.name).await?;
            signer = Some(verified);
            verified_key = tsig_key;
        }

        // RFC 6891, Section 6.1.3: BADVERS precedes every policy refusal.
        if let Some(rcode) = request.edns.format_error() {
            return Err(UpdateError::Edns { rcode });
        }

        // Unsigned UPDATE admits every reachable client; the service refuses it
        // under `tsig_required` after the authority check (RFC 2136, Section 3.1.1).
        let caller = match &verified_key {
            Some(tsig_key) => Caller::authenticate_tsig_key(cx, tsig_key)
                .await
                .map_err(NsupdateError::from)?,
            None => Caller::unsigned_dns(),
        };

        // A name no zone can carry is not served (RFC 2136, Section 3.1.2).
        let zone_name = zone_name.map_err(|error| UpdateError::NotAuth {
            reason: error.to_string(),
        })?;

        let update = Update {
            zone_name,
            zone_class: request.zone_class,
            prerequisites: &request.prerequisites,
            updates: &request.updates,
            message: query_data,
        };

        Ok(nsupdate::apply(cx, &caller, update).await?)
    }
    .await;

    (result, signer, verified_key)
}

/// Authenticate the request by the key `key_name` names: its TSIG verified,
/// the key comes back with the context that signs the response.
pub(crate) async fn authenticate_tsig_key(
    dns_cx: &DnsContext,
    query_data: &[u8],
    key_name: &str,
) -> Result<(Option<TsigKey>, ResponseSigner), UpdateError> {
    let tsig_key = tsig_key::find_by_wire_name(dns_cx.daemon(), key_name)
        .await
        .map_err(UpdateError::LoadTsigKey)?;

    // Verify unknown keys too, so the response encoder receives BADKEY.
    let signing_key = tsig_key.as_ref().map(TsigKey::to_signing_key).transpose()?;
    let signer = tsig::verify_tsig(query_data, signing_key)?;

    Ok((tsig_key, signer))
}

#[cfg(test)]
mod tests {
    use std::io;

    use bindizr_core::dns::message::Rcode;
    use bindizr_core::dns::nsupdate::parser::ValidateUpdateShapeError;

    use super::*;

    /// Verify that the complete parser and backend source chains are preserved through the
    /// DNS boundary.
    #[test]
    fn update_errors_retain_sources_across_layers() {
        use std::error::Error;

        let error = UpdateError::from(NsupdateError::from(ValidateUpdateShapeError::NonzeroTtl));
        let nsupdate = error
            .source()
            .unwrap()
            .downcast_ref::<NsupdateError>()
            .unwrap();

        assert_eq!(nsupdate.rcode(), Rcode::FORMERR);
        assert_eq!(
            nsupdate
                .source()
                .unwrap()
                .downcast_ref::<ValidateUpdateShapeError>(),
            Some(&ValidateUpdateShapeError::NonzeroTtl)
        );

        let error = UpdateError::from(NsupdateError::from(ServiceError::internal_with_source(
            "storage failed",
            io::Error::other("storage"),
        )));
        let nsupdate = error
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

        assert!(service.source().unwrap().is::<io::Error>());

        let error = UpdateError::from(TsigError::EmptySecret);

        assert!(matches!(
            error.source().unwrap().downcast_ref::<TsigError>(),
            Some(TsigError::EmptySecret)
        ));
    }
}
