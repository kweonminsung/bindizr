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
use bindizr_core::dns::tsig::{RequestSignature, TsigError};
use bindizr_core::dns::{nsupdate, tsig};
use bindizr_core::metrics::NsupdateResult;
use bindizr_core::model::transfer::TransferTransport;

use super::DnsContext;
use crate::dns::error::DnsError;
use crate::dns::server::nsupdate::update::UpdateError;
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

    let response = handle_nsupdate_request(
        dns_cx,
        client_addr,
        query_data,
        writer.transport(),
        ResponseLimit::STREAM,
    )
    .await?;

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

    let response = handle_nsupdate_request(
        dns_cx,
        client_addr,
        query_data,
        TransferTransport::Udp,
        limit,
    )
    .await?;

    socket.send_to(&response, target, limit).await?;

    Ok(())
}

/// Process an UPDATE and return its bounded response, preserving encoding failures.
async fn handle_nsupdate_request(
    dns_cx: &DnsContext,
    client_addr: SocketAddr,
    query_data: &[u8],
    transport: TransferTransport,
    limit: ResponseLimit,
) -> Result<Vec<u8>, DnsError> {
    let cx = dns_cx.daemon();

    let request = match UpdateRequest::parse(query_data) {
        Ok(request) => request,
        Err(error) => {
            log::warn!("NSUPDATE parse error from {client_addr}: {error}");
            let mut response_rcode = OptRcode::FORMERR;

            // RFC 8945, Section 5.2: a request whose key verifies is answered
            // under it, a FORMERR included; a bad key or MAC is its own error.
            let (signer, fudge) = match tsig::request_signature(query_data) {
                RequestSignature::Key { name, fudge } => {
                    match update::authenticate_tsig_key(dns_cx, &name, query_data).await {
                        Ok((_, signer)) => (Some(signer), fudge),
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

                                    return Ok(response);
                                }
                                Err(error) => {
                                    log::warn!(
                                        "NSUPDATE TSIG error encoding failed from {client_addr}: {error}"
                                    );
                                    response_rcode = OptRcode::SERVFAIL;

                                    (None, DEFAULT_FUDGE)
                                }
                            }
                        }
                        Err(error) => {
                            log::warn!("NSUPDATE key check failed from {client_addr}: {error}");

                            if matches!(&error, UpdateError::LoadTsigKey(_))
                                || matches!(
                                    &error,
                                    UpdateError::Tsig(error)
                                        if !matches!(error, TsigError::Malformed(_))
                                )
                            {
                                response_rcode = OptRcode::SERVFAIL;
                            }

                            (None, DEFAULT_FUDGE)
                        }
                    }
                }
                RequestSignature::Absent | RequestSignature::Malformed => (None, DEFAULT_FUDGE),
            };

            cx.metrics()
                .track_nsupdate(NsupdateResult::Rcode(response_rcode.rcode()));

            return Ok(nsupdate::build_response(
                query_data,
                response_rcode,
                None,
                signer,
                fudge,
                limit,
            )?);
        }
    };

    // The response TSIG echoes the request's fudge.
    let fudge = request
        .tsig
        .as_ref()
        .map_or(DEFAULT_FUDGE, |tsig| tsig.fudge);

    let (result, signer) = update::apply_update(dns_cx, request, query_data, transport).await;

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
                    return Ok(response);
                }
                Err(error) => {
                    log::warn!("NSUPDATE TSIG error encoding failed from {client_addr}: {error}");
                    (OptRcode::SERVFAIL, None)
                }
            }
        }
        Err(UpdateError::Edns(rcode)) => {
            log::info!("Refusing the EDNS of an NSUPDATE from {client_addr}");
            (rcode, None)
        }
        Err(UpdateError::NotSupported(reason)) => {
            log::info!("NSUPDATE refused from {client_addr}: {reason}");
            (OptRcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED))
        }
        Err(error @ UpdateError::Tsig(TsigError::Malformed(_))) => {
            log::warn!("NSUPDATE refused from {client_addr}: {error}");
            (OptRcode::REFUSED, Some(ExtendedErrorCode::PROHIBITED))
        }
        Err(error @ (UpdateError::NotAuth(_) | UpdateError::ZoneName { .. })) => {
            log::warn!("NSUPDATE notauth from {client_addr}: {error}");
            (
                OptRcode::NOTAUTH,
                Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
            )
        }
        Err(UpdateError::Nsupdate(error)) => {
            let rcode = error.rcode();
            let ede = match rcode {
                Rcode::REFUSED => Some(ExtendedErrorCode::PROHIBITED),
                Rcode::NOTAUTH => Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
                _ => None,
            };
            log::warn!("NSUPDATE {rcode} from {client_addr}: {error}");

            (rcode.into(), ede)
        }
        Err(error @ (UpdateError::LoadTsigKey(_) | UpdateError::Tsig(_))) => {
            log::warn!("NSUPDATE internal error from {client_addr}: {error}");
            (OptRcode::SERVFAIL, None)
        }
    };

    cx.metrics()
        .track_nsupdate(NsupdateResult::Rcode(rcode.rcode()));

    Ok(nsupdate::build_response(
        query_data, rcode, ede, signer, fudge, limit,
    )?)
}

#[cfg(test)]
mod tests;
