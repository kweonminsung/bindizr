//! nsupdate (RFC 2136) handling, including TSIG-authenticated
//! requests.

mod update;

use std::net::SocketAddr;

use bindizr_core::dns::message::{
    ExtendedErrorCode, Keepalive, OptRcode, QueryMetadata, Rcode, ResponseLimit,
};
use bindizr_core::dns::nsupdate::DEFAULT_FUDGE;
pub(crate) use bindizr_core::dns::nsupdate::is_nsupdate;
use bindizr_core::dns::nsupdate::parser::UpdateRequest;
use bindizr_core::dns::tsig::{RequestSignature, RequestTsig, TsigError, TsigRcode};
use bindizr_core::dns::{nsupdate, tsig};
use bindizr_core::metrics::NsupdateResult;
use bindizr_core::model::access_log::{AccessResult, AccessSource};
use bindizr_core::model::change::ChangeActor;
use bindizr_service::access::{AccessLogEntry, AccessLogErrorCode};
use bindizr_service::error::ErrorCode;
use bindizr_service::nsupdate::NsupdateError;
use bindizr_service::{Context, access, zone};
use chrono::Utc;

use crate::dns::error::DnsError;
use crate::dns::server::nsupdate::update::UpdateError;
use crate::dns::server::{DnsContext, auth};
use crate::dns::stream::ResponseWriter;
use crate::dns::udp::{ReplyTarget, UdpSocket};

/// Apply an nsupdate received over TCP and send its response.
pub(crate) async fn handle_tcp_nsupdate(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_addr: SocketAddr,
    query_data: &[u8],
) -> Result<(), DnsError> {
    log::info!("NSUPDATE {} request from {client_addr}", writer.transport());

    let response =
        handle_nsupdate_request(dns_cx, client_addr, query_data, ResponseLimit::STREAM).await?;

    writer.write_message(&response).await
}

/// Apply an nsupdate received over UDP and return its response.
pub(crate) async fn handle_udp_nsupdate(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    target: ReplyTarget,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let client_addr = target.client_addr;
    log::info!("NSUPDATE UDP request from {client_addr}");

    let limit = QueryMetadata::parse(query_data, Keepalive::None)
        .map_or(ResponseLimit::UDP, |metadata| metadata.response_limit());

    let response = handle_nsupdate_request(dns_cx, client_addr, query_data, limit).await?;

    socket.send_to(&response, target, limit).await?;

    Ok(())
}

/// Process an UPDATE and return its bounded response, preserving encoding
/// failures; every outcome leaves an access log row.
async fn handle_nsupdate_request(
    dns_cx: &DnsContext,
    client_addr: SocketAddr,
    query_data: &[u8],
    limit: ResponseLimit,
) -> Result<Vec<u8>, DnsError> {
    let cx = dns_cx.daemon();

    // Filled in as the request is read; its fields say how far it got.
    let mut access_log = AccessLogEntry {
        source: AccessSource::Nsupdate,
        client_addr: client_addr.ip().to_string(),
        method: "UPDATE".to_string(),
        target: String::new(),
        status: String::new(),
        result: AccessResult::Failed,
        caller: None,
        error: None,
        requested_at: Utc::now(),
    };

    let request = match UpdateRequest::parse(query_data) {
        Ok(request) => request,
        Err(error) => {
            log::warn!("NSUPDATE parse error from {client_addr}: {error}");
            access_log.error = Some(AccessLogErrorCode::Dns(OptRcode::FORMERR));
            let mut response_rcode = OptRcode::FORMERR;

            // RFC 8945, Section 5.2: a request whose key verifies is answered
            // under it, a FORMERR included; a bad key or MAC is its own error.
            let (signer, fudge) = match tsig::request_signature(query_data) {
                RequestSignature::Key(RequestTsig { name, fudge }) => {
                    match auth::verify_request_tsig(dns_cx, query_data, &name)
                        .await
                        .map_err(UpdateError::from)
                    {
                        Ok((tsig_key, signer)) => {
                            access_log.caller = Some(ChangeActor::TsigKey {
                                name: tsig_key.name,
                            });
                            (Some(signer), fudge)
                        }
                        Err(UpdateError::Tsig(TsigError::Rejected { rcode, key, time })) => {
                            match tsig::build_error_response(
                                query_data,
                                key.as_deref(),
                                rcode,
                                time,
                                limit,
                            ) {
                                Ok(response) => {
                                    log::warn!(
                                        "NSUPDATE TSIG rejected from {client_addr}: {rcode}"
                                    );
                                    cx.metrics().track_nsupdate(NsupdateResult::TsigFailed);
                                    save_tsig_rejected(cx, access_log, rcode);

                                    return Ok(response);
                                }
                                Err(error) => {
                                    log::warn!(
                                        "NSUPDATE TSIG error encoding failed from {client_addr}: {error}"
                                    );
                                    response_rcode = OptRcode::SERVFAIL;
                                    access_log.error =
                                        Some(AccessLogErrorCode::TsigResponseEncodingFailed);

                                    (None, DEFAULT_FUDGE)
                                }
                            }
                        }
                        // The key row would not load or decode: a server fault,
                        // as in the applied branch.
                        Err(error) => {
                            log::error!(
                                "NSUPDATE from {client_addr} failed with a server fault: {error:?}"
                            );

                            response_rcode = OptRcode::SERVFAIL;
                            access_log.error = Some(AccessLogErrorCode::TsigAuthenticationFailed);

                            (None, DEFAULT_FUDGE)
                        }
                    }
                }
                RequestSignature::Absent | RequestSignature::Malformed => (None, DEFAULT_FUDGE),
            };

            cx.metrics()
                .track_nsupdate(NsupdateResult::Rcode(response_rcode));

            let response =
                nsupdate::build_response(query_data, response_rcode, None, signer, fudge, limit);
            save_answered(cx, access_log, response_rcode, response.is_ok());

            return Ok(response?);
        }
    };

    // Parsed once where the text arrives; a refusal waits in the Result until
    // apply_update reports it, after the checks RFC 2136, Section 3 puts first.
    let zone_name = zone::normalize_name(&request.zone_name);

    // The zone as Bindizr spells it; text no zone name can carry stays as sent.
    access_log.target = zone_name
        .as_ref()
        .map_or_else(|_| request.zone_name.clone(), ToString::to_string);

    // The response TSIG echoes the request's fudge.
    let fudge = request
        .tsig
        .as_ref()
        .map_or(DEFAULT_FUDGE, |tsig| tsig.fudge);

    let (result, signer, tsig_key) =
        update::apply_update(dns_cx, request, zone_name, query_data).await;
    access_log.caller = tsig_key.map(|tsig_key| ChangeActor::TsigKey {
        name: tsig_key.name,
    });

    let (rcode, ede) = match result {
        Ok(changed) => {
            log::info!("NSUPDATE applied from {client_addr} (changed={changed})");
            (OptRcode::NOERROR, None)
        }
        // The handler composes TSIG rejections against the request (RFC 8945, Sections 5.2–5.3).
        Err(UpdateError::Tsig(TsigError::Rejected { rcode, key, time })) => {
            match tsig::build_error_response(query_data, key.as_deref(), rcode, time, limit) {
                Ok(response) => {
                    log::warn!("NSUPDATE TSIG rejected from {client_addr}: {rcode}");
                    cx.metrics().track_nsupdate(NsupdateResult::TsigFailed);
                    save_tsig_rejected(cx, access_log, rcode);

                    return Ok(response);
                }
                Err(error) => {
                    log::warn!("NSUPDATE TSIG error encoding failed from {client_addr}: {error}");
                    access_log.error = Some(AccessLogErrorCode::TsigResponseEncodingFailed);
                    (OptRcode::SERVFAIL, None)
                }
            }
        }
        Err(UpdateError::Edns { rcode }) => {
            log::info!("Refusing the EDNS of an NSUPDATE from {client_addr}");
            access_log.error = Some(AccessLogErrorCode::Dns(rcode));
            (rcode, None)
        }
        Err(error @ UpdateError::NotAuth(_)) => {
            log::warn!("NSUPDATE notauth from {client_addr}: {error}");
            access_log.error = Some(AccessLogErrorCode::Dns(OptRcode::NOTAUTH));
            (
                OptRcode::NOTAUTH,
                Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
            )
        }
        Err(UpdateError::Nsupdate(error)) => {
            let rcode = error
                .rcode()
                .unwrap_or_else(|service_error| update_rcode(service_error.code()));
            let ede = match rcode {
                Rcode::REFUSED => Some(ExtendedErrorCode::PROHIBITED),
                Rcode::NOTAUTH => Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
                _ => None,
            };
            if let NsupdateError::Service(service_error) = &error
                && service_error.code().is_internal()
            {
                log::error!(
                    "NSUPDATE from {client_addr} failed with a server fault: {service_error:?}"
                );
            } else {
                log::warn!("NSUPDATE {rcode} from {client_addr}: {error}");
            }
            access_log.error = Some(match &error {
                NsupdateError::Service(error) => AccessLogErrorCode::Service(error.code()),
                _ => AccessLogErrorCode::Dns(rcode.into()),
            });

            (rcode.into(), ede)
        }
        Err(error @ (UpdateError::LoadTsigKey(_) | UpdateError::Tsig(_))) => {
            log::error!("NSUPDATE from {client_addr} failed with a server fault: {error:?}");
            access_log.error = Some(AccessLogErrorCode::TsigAuthenticationFailed);
            (OptRcode::SERVFAIL, None)
        }
    };

    cx.metrics().track_nsupdate(NsupdateResult::Rcode(rcode));

    let response = nsupdate::build_response(query_data, rcode, ede, signer, fudge, limit);
    save_answered(cx, access_log, rcode, response.is_ok());

    Ok(response?)
}

/// Return the RCODE an UPDATE answers a service failure with. Every code is
/// spelled out, so a new one has to choose its RCODE here.
fn update_rcode(code: ErrorCode) -> Rcode {
    match code {
        // A server fault, which the requester may retry.
        ErrorCode::Internal | ErrorCode::DnssecSigningFailed => Rcode::SERVFAIL,
        // A refusal by policy: grants, zone rules, or a stored conflict
        // (RFC 2136, Section 3.3; zone-policy failures are REFUSED, not malformed RDATA).
        ErrorCode::InvalidInput
        | ErrorCode::InvalidZoneField
        | ErrorCode::InvalidRecordName
        | ErrorCode::InvalidRecordValue
        | ErrorCode::InvalidJsonBody
        | ErrorCode::ZoneConflict
        | ErrorCode::RecordConflict
        | ErrorCode::TokenConflict
        | ErrorCode::EndpointNotFound
        | ErrorCode::MethodNotAllowed
        | ErrorCode::ZoneNotFound
        | ErrorCode::RecordNotFound
        | ErrorCode::TokenNotFound
        | ErrorCode::VersionNotFound
        | ErrorCode::SecondaryNotFound
        | ErrorCode::SecondaryConflict
        | ErrorCode::TsigKeyNotFound
        | ErrorCode::TsigKeyConflict
        | ErrorCode::TsigKeyInUse
        | ErrorCode::RoleNotFound
        | ErrorCode::RoleConflict
        | ErrorCode::RoleInUse
        | ErrorCode::RoleGrantNotFound
        | ErrorCode::DnssecAlreadyEnabled
        | ErrorCode::DnssecNotEnabled
        | ErrorCode::DnssecRolloverInProgress
        | ErrorCode::DnssecNoRolloverInProgress
        | ErrorCode::DnssecDsPublished
        | ErrorCode::DnssecDsNotPublished
        | ErrorCode::DnssecDsUnverified
        | ErrorCode::DnssecPolicyNotFound
        | ErrorCode::DnssecPolicyConflict
        | ErrorCode::DnssecPolicyInUse
        | ErrorCode::Unauthorized
        | ErrorCode::InvalidToken
        | ErrorCode::Forbidden
        | ErrorCode::PayloadTooLarge
        | ErrorCode::UnsupportedMediaType => Rcode::REFUSED,
    }
}

/// Save a TSIG rejection's fixed code; an unverified key names no caller.
fn save_tsig_rejected(cx: &Context, mut access_log: AccessLogEntry, rcode: TsigRcode) {
    access_log.error = Some(AccessLogErrorCode::Tsig(rcode));
    access_log.status = rcode.to_string();
    access_log.result = AccessResult::Denied;
    access::save(cx, access_log);
}

/// Save an UPDATE answered with `rcode`: REFUSED is a denial, any other error
/// a failure, and so is a response that could not be encoded.
fn save_answered(cx: &Context, mut access_log: AccessLogEntry, rcode: OptRcode, encoded: bool) {
    access_log.status = rcode.to_string();
    access_log.result = if !encoded {
        AccessResult::Failed
    } else if rcode == OptRcode::NOERROR {
        AccessResult::Ok
    } else if rcode == OptRcode::REFUSED {
        AccessResult::Denied
    } else {
        AccessResult::Failed
    };

    if !encoded {
        access_log.error = Some(AccessLogErrorCode::ResponseEncodingFailed);
    }

    access::save(cx, access_log);
}

#[cfg(test)]
mod tests;
