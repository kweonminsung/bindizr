//! RFC 2136 dynamic DNS update (nsupdate) handling, including TSIG-authenticated
//! requests.

mod update;

use std::net::SocketAddr;

pub(crate) use bindizr_core::dns::nsupdate::is_nsupdate;
use bindizr_core::{
    dns::{
        message::{Edns, ExtendedErrorCode, OptRcode, Rcode},
        nsupdate::{DEFAULT_FUDGE, build_response},
        tsig::{RequestSignature, request_signature},
    },
    metrics::NsupdateResult,
};
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::dns::{error::XfrError, server::DnsContext, stream::DnsStream};

/// Why an UPDATE was not answered, for the listener's log.
#[derive(Debug, Error)]
pub(crate) enum NsupdateError {
    #[error("failed to build NSUPDATE TCP response")]
    BuildResponse,
    #[error("failed to write NSUPDATE TCP response: {0}")]
    WriteTcp(#[source] XfrError),
    #[error("failed to write NSUPDATE UDP response: {0}")]
    SendUdp(#[source] std::io::Error),
}

/// Apply a dynamic update received over TCP and send its response.
pub(crate) async fn handle_tcp_nsupdate(
    dns_cx: &DnsContext,
    stream: &mut DnsStream,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), NsupdateError> {
    log::info!("NSUPDATE TCP request from {}", client_addr);
    let response = handle_nsupdate_request(dns_cx, query_data, client_addr)
        .await
        .ok_or(NsupdateError::BuildResponse)?;
    crate::dns::wire::write_tcp_message(stream, &response)
        .await
        .map_err(NsupdateError::WriteTcp)
}

/// Apply a dynamic update received over UDP and return its response.
pub(crate) async fn handle_udp_nsupdate(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), NsupdateError> {
    log::info!("NSUPDATE UDP request from {}", client_addr);

    let response = match handle_nsupdate_request(dns_cx, query_data, client_addr).await {
        Some(resp) => resp,
        None => {
            log::warn!("Ignored malformed NSUPDATE packet from {}", client_addr);
            return Ok(());
        }
    };

    socket
        .send_to(&response, client_addr)
        .await
        .map_err(NsupdateError::SendUdp)?;
    Ok(())
}

/// Process an UPDATE request and return the complete wire response, or `None`
/// for a message too malformed to answer.
async fn handle_nsupdate_request(
    dns_cx: &DnsContext,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Option<Vec<u8>> {
    let cx = dns_cx.daemon();
    let parsed = match bindizr_core::dns::nsupdate::parser::UpdateRequest::parse(query_data) {
        Ok(req) => req,
        Err(e) => {
            log::warn!("NSUPDATE parse error from {}: {}", client_addr, e);
            // RFC 8945, Section 5.2: a request whose key verifies is answered
            // under it, a FORMERR included; a bad key or MAC is its own error.
            let (signer, fudge) = match request_signature(query_data) {
                RequestSignature::Key { name, fudge } => {
                    match update::verify_signer(dns_cx, &name, query_data).await {
                        Ok((_, signer)) => (Some(signer), fudge),
                        Err(update::UpdateError::TsigFailed { msg, response }) => {
                            log::warn!("NSUPDATE notauth from {}: {}", client_addr, msg);
                            cx.metrics().track_nsupdate(NsupdateResult::TsigFailed);
                            return Some(response);
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
            return build_response(query_data, OptRcode::FORMERR, None, signer, fudge);
        }
    };

    // The response TSIG echoes the request's fudge.
    let fudge = parsed
        .tsig
        .as_ref()
        .map_or(DEFAULT_FUDGE, |tsig| tsig.fudge);

    // RFC 6891, Sections 6.1.1 and 6.1.3: an OPT the server cannot take is
    // answered before the update is read.
    let edns_rcode = match parsed.edns {
        Edns::Absent | Edns::Present { .. } => None,
        Edns::Malformed => Some(OptRcode::FORMERR),
        Edns::UnsupportedVersion(_) => Some(OptRcode::BADVERS),
    };
    if let Some(rcode) = edns_rcode {
        log::info!("Refusing the EDNS of an NSUPDATE from {}", client_addr);
        cx.metrics()
            .track_nsupdate(NsupdateResult::Rcode(rcode.rcode()));
        return build_response(query_data, rcode, None, None, fudge);
    }
    let (result, signer) = update::apply_update(dns_cx, parsed, query_data).await;

    let (rcode, ede) = match result {
        Ok(changed) => {
            log::info!(
                "NSUPDATE applied from {} (changed={})",
                client_addr,
                changed
            );
            (Rcode::NOERROR, None)
        }
        // TSIG failures carry their own complete response, built against the
        // request's TSIG record (RFC 8945, Sections 5.2–5.3).
        Err(update::UpdateError::TsigFailed { msg, response }) => {
            log::warn!("NSUPDATE notauth from {}: {}", client_addr, msg);
            cx.metrics().track_nsupdate(NsupdateResult::TsigFailed);
            return Some(response);
        }
        Err(update::UpdateError::FormErr(msg)) => {
            log::warn!("NSUPDATE formerr from {}: {}", client_addr, msg);
            (Rcode::FORMERR, None)
        }
        Err(update::UpdateError::Refused(msg)) => {
            log::warn!("NSUPDATE refused from {}: {}", client_addr, msg);
            (Rcode::REFUSED, Some(ExtendedErrorCode::PROHIBITED))
        }
        Err(update::UpdateError::YxDomain(msg)) => {
            log::warn!("NSUPDATE yxdomain from {}: {}", client_addr, msg);
            (Rcode::YXDOMAIN, None)
        }
        Err(update::UpdateError::YxRrset(msg)) => {
            log::warn!("NSUPDATE yxrrset from {}: {}", client_addr, msg);
            (Rcode::YXRRSET, None)
        }
        Err(update::UpdateError::NxDomain(msg)) => {
            log::warn!("NSUPDATE nxdomain from {}: {}", client_addr, msg);
            (Rcode::NXDOMAIN, None)
        }
        Err(update::UpdateError::NxRrset(msg)) => {
            log::warn!("NSUPDATE nxrrset from {}: {}", client_addr, msg);
            (Rcode::NXRRSET, None)
        }
        Err(update::UpdateError::NotAuth(msg)) => {
            log::warn!("NSUPDATE notauth from {}: {}", client_addr, msg);
            (Rcode::NOTAUTH, Some(ExtendedErrorCode::NOT_AUTHORITATIVE))
        }
        Err(update::UpdateError::NotZone(msg)) => {
            log::warn!("NSUPDATE notzone from {}: {}", client_addr, msg);
            (Rcode::NOTZONE, None)
        }
        Err(err @ update::UpdateError::Internal { .. }) => {
            log::warn!("NSUPDATE internal error from {}: {}", client_addr, err);
            (Rcode::SERVFAIL, None)
        }
    };

    cx.metrics().track_nsupdate(NsupdateResult::Rcode(rcode));
    build_response(query_data, OptRcode::from(rcode), ede, signer, fudge)
}
