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
    log_info, log_warn,
    metrics::metrics,
};
use tokio::net::{TcpStream, UdpSocket};

pub(crate) async fn handle_tcp_nsupdate(
    stream: &mut TcpStream,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), String> {
    log_info!("NSUPDATE TCP request from {}", client_addr);

    let response = handle_nsupdate_request(query_data, client_addr)
        .await
        .ok_or_else(|| "Failed to build NSUPDATE TCP response".to_string())?;

    crate::dns::wire::write_tcp_message(stream, &response)
        .await
        .map_err(|e| format!("Failed to write NSUPDATE TCP response: {}", e))
}

pub(crate) async fn handle_udp_nsupdate(
    socket: &UdpSocket,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), String> {
    log_info!("NSUPDATE UDP request from {}", client_addr);

    let response = match handle_nsupdate_request(query_data, client_addr).await {
        Some(resp) => resp,
        None => {
            log_warn!("Ignored malformed NSUPDATE packet from {}", client_addr);
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
    let parsed = match bindizr_core::dns::nsupdate::parser::parse_update_request(query_data) {
        Ok(req) => req,
        Err(e) => {
            log_warn!("NSUPDATE parse error from {}: {}", client_addr, e);
            record_nsupdate_metric("formerr");
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
            log_info!(
                "NSUPDATE applied from {} (changed={})",
                client_addr,
                changed
            );
            Rcode::NOERROR
        }
        // TSIG failures carry their own complete response, built against the
        // request's TSIG record (RFC 8945, Sections 5.2–5.3).
        Err(update::UpdateError::TsigFailed { msg, response }) => {
            log_warn!("NSUPDATE notauth from {}: {}", client_addr, msg);
            record_nsupdate_metric("tsig_failed");
            return Some(response);
        }
        Err(update::UpdateError::Refused(msg)) => {
            log_warn!("NSUPDATE refused from {}: {}", client_addr, msg);
            Rcode::REFUSED
        }
        Err(update::UpdateError::YxDomain(msg)) => {
            log_warn!("NSUPDATE yxdomain from {}: {}", client_addr, msg);
            Rcode::YXDOMAIN
        }
        Err(update::UpdateError::YxRrset(msg)) => {
            log_warn!("NSUPDATE yxrrset from {}: {}", client_addr, msg);
            Rcode::YXRRSET
        }
        Err(update::UpdateError::NxDomain(msg)) => {
            log_warn!("NSUPDATE nxdomain from {}: {}", client_addr, msg);
            Rcode::NXDOMAIN
        }
        Err(update::UpdateError::NxRrset(msg)) => {
            log_warn!("NSUPDATE nxrrset from {}: {}", client_addr, msg);
            Rcode::NXRRSET
        }
        Err(update::UpdateError::NotZone(msg)) => {
            log_warn!("NSUPDATE notzone from {}: {}", client_addr, msg);
            Rcode::NOTZONE
        }
        Err(update::UpdateError::Internal(msg)) => {
            log_warn!("NSUPDATE internal error from {}: {}", client_addr, msg);
            Rcode::SERVFAIL
        }
    };

    record_nsupdate_metric(rcode_label(rcode));
    build_response(query_data, rcode, signer, fudge)
}

fn record_nsupdate_metric(result: &str) {
    metrics()
        .nsupdate_requests_total
        .with_label_values(&[result])
        .inc();
}

// Bounded label values from the response code, never the free-form message.
fn rcode_label(rcode: Rcode) -> &'static str {
    match rcode {
        Rcode::NOERROR => "noerror",
        Rcode::FORMERR => "formerr",
        Rcode::REFUSED => "refused",
        Rcode::YXDOMAIN => "yxdomain",
        Rcode::YXRRSET => "yxrrset",
        Rcode::NXDOMAIN => "nxdomain",
        Rcode::NXRRSET => "nxrrset",
        Rcode::NOTZONE => "notzone",
        Rcode::SERVFAIL => "servfail",
        _ => "other",
    }
}
