//! nsupdate (RFC 2136) handling, including TSIG-authenticated
//! requests.

mod update;

use std::net::SocketAddr;

pub(crate) use bindizr_core::dns::nsupdate::is_nsupdate;
use bindizr_core::{
    dns::{
        message::{ExtendedErrorCode, Keepalive, OptRcode, QueryMetadata, Rcode, ResponseLimit},
        nsupdate::{DEFAULT_FUDGE, build_response},
        tsig::{RequestSignature, TsigError, request_signature},
    },
    metrics::NsupdateResult,
    model::transfer::TransferTransport,
};

use crate::dns::{
    error::DnsError,
    server::DnsContext,
    stream::ResponseWriter,
    udp::{ReplyTarget, UdpSocket},
};

/// Apply an nsupdate received over TCP and send its response.
pub(crate) async fn handle_tcp_nsupdate(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), DnsError> {
    log::info!(
        "NSUPDATE {} request from {}",
        writer.transport(),
        client_addr
    );

    let response = handle_nsupdate_request(
        dns_cx,
        query_data,
        client_addr,
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
    query_data: &[u8],
    target: ReplyTarget,
) -> Result<(), DnsError> {
    let client_addr = target.client_addr;
    log::info!("NSUPDATE UDP request from {}", client_addr);

    let limit = QueryMetadata::parse(query_data, Keepalive::None)
        .map_or(ResponseLimit::UDP, |metadata| metadata.response_limit());

    let response = handle_nsupdate_request(
        dns_cx,
        query_data,
        client_addr,
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
    query_data: &[u8],
    client_addr: SocketAddr,
    transport: TransferTransport,
    limit: ResponseLimit,
) -> Result<Vec<u8>, DnsError> {
    let cx = dns_cx.daemon();

    let parsed = match bindizr_core::dns::nsupdate::parser::UpdateRequest::parse(query_data) {
        Ok(request) => request,
        Err(error) => {
            log::warn!("NSUPDATE parse error from {}: {}", client_addr, error);
            let mut response_rcode = OptRcode::FORMERR;

            // RFC 8945, Section 5.2: a request whose key verifies is answered
            // under it, a FORMERR included; a bad key or MAC is its own error.
            let (signer, fudge) = match request_signature(query_data) {
                RequestSignature::Key { name, fudge } => {
                    match update::authenticate_tsig_key(dns_cx, &name, query_data).await {
                        Ok((_, signer)) => (Some(signer), fudge),
                        Err(update::UpdateError::Tsig(TsigError::Rejected {
                            rcode,
                            key,
                            time,
                        })) => {
                            match bindizr_core::dns::tsig::build_error_response(
                                query_data,
                                key.as_deref(),
                                rcode,
                                time,
                                limit,
                            ) {
                                Ok(response) => {
                                    log::warn!(
                                        "NSUPDATE TSIG rejected from {}: {}",
                                        client_addr,
                                        rcode
                                    );
                                    cx.metrics().track_nsupdate(NsupdateResult::TsigFailed);

                                    return Ok(response);
                                }
                                Err(error) => {
                                    log::warn!(
                                        "NSUPDATE TSIG error encoding failed from {}: {}",
                                        client_addr,
                                        error
                                    );
                                    response_rcode = OptRcode::SERVFAIL;

                                    (None, DEFAULT_FUDGE)
                                }
                            }
                        }
                        Err(error) => {
                            log::warn!("NSUPDATE key check failed from {}: {}", client_addr, error);

                            if matches!(&error, update::UpdateError::LoadTsigKey(_))
                                || matches!(
                                    &error,
                                    update::UpdateError::Tsig(error)
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

            return Ok(build_response(
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
    let fudge = parsed
        .tsig
        .as_ref()
        .map_or(DEFAULT_FUDGE, |tsig| tsig.fudge);

    let (result, signer) = update::apply_update(dns_cx, parsed, query_data, transport).await;

    let (rcode, ede) = match result {
        Ok(changed) => {
            log::info!(
                "NSUPDATE applied from {} (changed={})",
                client_addr,
                changed
            );
            (OptRcode::NOERROR, None)
        }
        // The handler composes TSIG rejections against the request (RFC 8945, Sections 5.2–5.3).
        Err(update::UpdateError::Tsig(TsigError::Rejected { rcode, key, time })) => {
            match bindizr_core::dns::tsig::build_error_response(
                query_data,
                key.as_deref(),
                rcode,
                time,
                limit,
            ) {
                Ok(response) => {
                    log::warn!("NSUPDATE TSIG rejected from {}: {}", client_addr, rcode);
                    cx.metrics().track_nsupdate(NsupdateResult::TsigFailed);
                    return Ok(response);
                }
                Err(error) => {
                    log::warn!(
                        "NSUPDATE TSIG error encoding failed from {}: {}",
                        client_addr,
                        error
                    );
                    (OptRcode::SERVFAIL, None)
                }
            }
        }
        Err(update::UpdateError::Edns(rcode)) => {
            log::info!("Refusing the EDNS of an NSUPDATE from {}", client_addr);
            (rcode, None)
        }
        Err(update::UpdateError::NotSupported(message)) => {
            log::info!("NSUPDATE refused from {}: {}", client_addr, message);
            (OptRcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED))
        }
        Err(error @ update::UpdateError::Tsig(TsigError::Malformed(_))) => {
            log::warn!("NSUPDATE refused from {}: {}", client_addr, error);
            (OptRcode::REFUSED, Some(ExtendedErrorCode::PROHIBITED))
        }
        Err(error @ (update::UpdateError::NotAuth(_) | update::UpdateError::ZoneName { .. })) => {
            log::warn!("NSUPDATE notauth from {}: {}", client_addr, error);
            (
                OptRcode::NOTAUTH,
                Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
            )
        }
        Err(update::UpdateError::Nsupdate(error)) => {
            let rcode = error.rcode();
            let ede = match rcode {
                Rcode::REFUSED => Some(ExtendedErrorCode::PROHIBITED),
                Rcode::NOTAUTH => Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
                _ => None,
            };
            log::warn!("NSUPDATE {} from {}: {}", rcode, client_addr, error);

            (rcode.into(), ede)
        }
        Err(error @ (update::UpdateError::LoadTsigKey(_) | update::UpdateError::Tsig(_))) => {
            log::warn!("NSUPDATE internal error from {}: {}", client_addr, error);
            (OptRcode::SERVFAIL, None)
        }
    };

    cx.metrics()
        .track_nsupdate(NsupdateResult::Rcode(rcode.rcode()));

    Ok(build_response(
        query_data, rcode, ede, signer, fudge, limit,
    )?)
}

#[cfg(test)]
mod tests;
