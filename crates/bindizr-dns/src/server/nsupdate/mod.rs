//! RFC 2136 dynamic DNS update (nsupdate) handling, including TSIG-authenticated
//! requests.

mod auth;
mod parser;
mod prerequisite;
mod update;

use std::net::SocketAddr;

use domain::{
    base::{
        Message, MessageBuilder,
        iana::{Opcode, Rcode},
    },
    rdata::tsig::Time48,
};
use tokio::net::{TcpStream, UdpSocket};

use crate::{log_info, log_warn, metrics::metrics};

/// Response-TSIG fudge for requests whose own fudge is unavailable
/// (RFC 8945, Section 10 suggested default).
const DEFAULT_FUDGE: u16 = 300;

pub(crate) fn is_nsupdate(message: &[u8]) -> bool {
    Message::from_octets(message).is_ok_and(|message| message.header().opcode() == Opcode::UPDATE)
}

pub(crate) async fn handle_tcp_nsupdate(
    stream: &mut TcpStream,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), String> {
    log_info!("NSUPDATE TCP request from {}", client_addr);

    let response = handle_nsupdate_request(query_data, client_addr)
        .await
        .ok_or_else(|| "Failed to build NSUPDATE TCP response".to_string())?;

    crate::wire::write_tcp_message(stream, &response)
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
    let parsed = match parser::parse_update_request(query_data) {
        Ok(req) => req,
        // A name bindizr will not represent is a policy refusal, not a
        // malformed message: FORMERR would tell the client its UPDATE was
        // unreadable (RFC 1035, Section 4.1.1).
        Err(parser::ParseError::UnsupportedName) => {
            log_warn!(
                "NSUPDATE refused from {}: unsupported domain name",
                client_addr
            );
            count_nsupdate("refused");
            return build_response(query_data, Rcode::REFUSED, None, DEFAULT_FUDGE);
        }
        Err(e) => {
            log_warn!("NSUPDATE parse error from {}: {}", client_addr, e);
            count_nsupdate("formerr");
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
        Ok(update::UpdateResult::Applied { changed }) => {
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
            count_nsupdate("tsig_failed");
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

    count_nsupdate(rcode_label(rcode));
    build_response(query_data, rcode, signer, fudge)
}

fn count_nsupdate(result: &str) {
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

/// Build the response: request ID/opcode/question echoed, RCODE set, and a
/// TSIG appended once the request's TSIG was validated — every response to a
/// signed request must be signed (RFC 8945, Section 5.3).
fn build_response(
    query_data: &[u8],
    rcode: Rcode,
    signer: Option<auth::ResponseSigner>,
    fudge: u16,
) -> Option<Vec<u8>> {
    let msg = Message::from_octets(query_data).ok()?;
    let answer = MessageBuilder::new_vec().start_answer(&msg, rcode).ok()?;
    let mut additional = answer.additional();

    if let Some(signer) = signer {
        signer
            .answer_with_fudge(&mut additional, Time48::now(), fudge)
            .ok()?;
    }

    Some(additional.finish())
}

#[cfg(test)]
mod tests;
