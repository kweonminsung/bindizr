//! RFC 2136 dynamic DNS update (nsupdate) handling, including TSIG-authenticated
//! requests.

mod update;

use std::net::SocketAddr;

pub(crate) use bindizr_core::dns::nsupdate::is_nsupdate;
use bindizr_core::{
    dns::{
        message::Rcode,
        nsupdate::{DEFAULT_FUDGE, build_response},
    },
    metrics::{NsupdateResult, track_nsupdate},
};
use tokio::net::{TcpStream, UdpSocket};

/// Apply a dynamic update received over TCP and send its response.
pub(crate) async fn handle_tcp_nsupdate(
    stream: &mut TcpStream,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), String> {
    log::info!("NSUPDATE TCP request from {}", client_addr);

    let response = handle_nsupdate_request(query_data, client_addr)
        .await
        .ok_or_else(|| "Failed to build NSUPDATE TCP response".to_string())?;

    crate::dns::wire::write_tcp_message(stream, &response)
        .await
        .map_err(|e| format!("Failed to write NSUPDATE TCP response: {}", e))
}

/// Apply a dynamic update received over UDP and return its response.
pub(crate) async fn handle_udp_nsupdate(
    socket: &UdpSocket,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), String> {
    log::info!("NSUPDATE UDP request from {}", client_addr);

    let response = match handle_nsupdate_request(query_data, client_addr).await {
        Some(resp) => resp,
        None => {
            log::warn!("Ignored malformed NSUPDATE packet from {}", client_addr);
            return Ok(());
        }
    };

    socket
        .send_to(&response, client_addr)
        .await
        .map_err(|e| format!("Failed to write NSUPDATE UDP response: {}", e))?;

    Ok(())
}

/// Process an UPDATE request and return the complete wire response, or `None`
/// for a message too malformed to answer.
async fn handle_nsupdate_request(query_data: &[u8], client_addr: SocketAddr) -> Option<Vec<u8>> {
    let parsed = match bindizr_core::dns::nsupdate::parser::UpdateRequest::parse(query_data) {
        Ok(req) => req,
        Err(e) => {
            log::warn!("NSUPDATE parse error from {}: {}", client_addr, e);
            track_nsupdate(NsupdateResult::Rcode(Rcode::FORMERR));
            return build_response(query_data, Rcode::FORMERR, None, DEFAULT_FUDGE);
        }
    };

    // The response TSIG echoes the request's fudge.
    let fudge = parsed
        .tsig
        .as_ref()
        .map_or(DEFAULT_FUDGE, |tsig| tsig.fudge);
    let (result, signer) = update::apply_update(parsed, query_data).await;

    let rcode = match result {
        Ok(changed) => {
            log::info!(
                "NSUPDATE applied from {} (changed={})",
                client_addr,
                changed
            );
            Rcode::NOERROR
        }
        // TSIG failures carry their own complete response, built against the
        // request's TSIG record (RFC 8945, Sections 5.2–5.3).
        Err(update::UpdateError::TsigFailed { msg, response }) => {
            log::warn!("NSUPDATE notauth from {}: {}", client_addr, msg);
            track_nsupdate(NsupdateResult::TsigFailed);
            return Some(response);
        }
        Err(update::UpdateError::Refused(msg)) => {
            log::warn!("NSUPDATE refused from {}: {}", client_addr, msg);
            Rcode::REFUSED
        }
        Err(update::UpdateError::YxDomain(msg)) => {
            log::warn!("NSUPDATE yxdomain from {}: {}", client_addr, msg);
            Rcode::YXDOMAIN
        }
        Err(update::UpdateError::YxRrset(msg)) => {
            log::warn!("NSUPDATE yxrrset from {}: {}", client_addr, msg);
            Rcode::YXRRSET
        }
        Err(update::UpdateError::NxDomain(msg)) => {
            log::warn!("NSUPDATE nxdomain from {}: {}", client_addr, msg);
            Rcode::NXDOMAIN
        }
        Err(update::UpdateError::NxRrset(msg)) => {
            log::warn!("NSUPDATE nxrrset from {}: {}", client_addr, msg);
            Rcode::NXRRSET
        }
        Err(update::UpdateError::NotZone(msg)) => {
            log::warn!("NSUPDATE notzone from {}: {}", client_addr, msg);
            Rcode::NOTZONE
        }
        Err(update::UpdateError::Internal(msg)) => {
            log::warn!("NSUPDATE internal error from {}: {}", client_addr, msg);
            Rcode::SERVFAIL
        }
    };

    track_nsupdate(NsupdateResult::Rcode(rcode));
    build_response(query_data, rcode, signer, fudge)
}
