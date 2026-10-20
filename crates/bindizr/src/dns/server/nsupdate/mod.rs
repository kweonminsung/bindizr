//! nsupdate (RFC 2136) handling, including TSIG-authenticated
//! requests.

mod update;

use std::net::SocketAddr;

pub(crate) use bindizr_core::dns::nsupdate::is_nsupdate;
use bindizr_core::{
    dns::{
        message::{ExtendedErrorCode, Keepalive, OptRcode, ParsedQuery, Rcode, ResponseLimit},
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

    let limit = ParsedQuery::parse(query_data, Keepalive::None)
        .map_or(ResponseLimit::UDP, |query| query.response_limit());
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
        Ok(req) => req,
        Err(e) => {
            log::warn!("NSUPDATE parse error from {}: {}", client_addr, e);
            // RFC 8945, Section 5.2: a request whose key verifies is answered
            // under it, a FORMERR included; a bad key or MAC is its own error.
            let (signer, fudge) = match request_signature(query_data) {
                RequestSignature::Key { name, fudge } => {
                    match update::authenticate_tsig_key(dns_cx, &name, query_data, limit).await {
                        Ok((_, signer)) => (Some(signer), fudge),
                        Err(update::UpdateError::Tsig(TsigError::Rejected { rcode, response })) => {
                            log::warn!("NSUPDATE TSIG rejected from {}: {}", client_addr, rcode);
                            cx.metrics().track_nsupdate(NsupdateResult::TsigFailed);
                            return Ok(response);
                        }
                        Err(err) => {
                            log::warn!("NSUPDATE key check failed from {}: {}", client_addr, err);
                            (None, DEFAULT_FUDGE)
                        }
                    }
                }
                RequestSignature::Absent | RequestSignature::Malformed => (None, DEFAULT_FUDGE),
            };
            cx.metrics()
                .track_nsupdate(NsupdateResult::Rcode(Rcode::FORMERR));
            return Ok(build_response(
                query_data,
                OptRcode::FORMERR,
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

    let (result, signer) = update::apply_update(dns_cx, parsed, query_data, transport, limit).await;

    let (rcode, ede) = match result {
        Ok(changed) => {
            log::info!(
                "NSUPDATE applied from {} (changed={})",
                client_addr,
                changed
            );
            (OptRcode::NOERROR, None)
        }
        // TSIG failures carry their own complete response, built against the
        // request's TSIG record (RFC 8945, Sections 5.2–5.3).
        Err(update::UpdateError::Tsig(TsigError::Rejected { rcode, response })) => {
            log::warn!("NSUPDATE TSIG rejected from {}: {}", client_addr, rcode);
            cx.metrics().track_nsupdate(NsupdateResult::TsigFailed);
            return Ok(response);
        }
        Err(update::UpdateError::Edns(rcode)) => {
            log::info!("Refusing the EDNS of an NSUPDATE from {}", client_addr);
            (rcode, None)
        }
        Err(update::UpdateError::NotSupported(msg)) => {
            log::info!("NSUPDATE refused from {}: {}", client_addr, msg);
            (OptRcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED))
        }
        Err(err @ update::UpdateError::Tsig(TsigError::Malformed(_))) => {
            log::warn!("NSUPDATE refused from {}: {}", client_addr, err);
            (OptRcode::REFUSED, Some(ExtendedErrorCode::PROHIBITED))
        }
        Err(err @ (update::UpdateError::NotAuth(_) | update::UpdateError::ZoneName { .. })) => {
            log::warn!("NSUPDATE notauth from {}: {}", client_addr, err);
            (
                OptRcode::NOTAUTH,
                Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
            )
        }
        Err(update::UpdateError::Nsupdate(err)) => {
            let rcode = err.rcode();
            let ede = match rcode {
                Rcode::REFUSED => Some(ExtendedErrorCode::PROHIBITED),
                Rcode::NOTAUTH => Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
                _ => None,
            };
            log::warn!("NSUPDATE {} from {}: {}", rcode, client_addr, err);
            (rcode.into(), ede)
        }
        Err(err @ (update::UpdateError::LoadTsigKey(_) | update::UpdateError::Tsig(_))) => {
            log::warn!("NSUPDATE internal error from {}: {}", client_addr, err);
            (OptRcode::SERVFAIL, None)
        }
    };

    cx.metrics()
        .track_nsupdate(NsupdateResult::Rcode(rcode.rcode()));
    Ok(build_response(
        query_data, rcode, ede, signer, fudge, limit,
    )?)
}
