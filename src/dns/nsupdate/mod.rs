mod auth;
mod parser;
mod prerequisite;
mod update;

use crate::{log_info, log_warn};
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};

const DNS_HEADER_LEN: usize = 12;
const DNS_OPCODE_UPDATE: u8 = 5;

const RCODE_NOERROR: u8 = 0;
const RCODE_FORMERR: u8 = 1;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;
const RCODE_YXDOMAIN: u8 = 6;
const RCODE_YXRRSET: u8 = 7;
const RCODE_NXRRSET: u8 = 8;
const RCODE_NOTZONE: u8 = 10;

pub fn is_nsupdate(message: &[u8]) -> bool {
    if message.len() < DNS_HEADER_LEN {
        return false;
    }

    let opcode = (message[2] >> 3) & 0x0f;
    opcode == DNS_OPCODE_UPDATE
}

pub async fn handle_tcp_nsupdate(
    stream: &mut TcpStream,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), String> {
    log_info!("NSUPDATE TCP request from {}", client_addr);

    let rcode = handle_nsupdate_request(query_data, client_addr).await;
    let response = build_response(query_data, rcode)
        .ok_or_else(|| "Failed to build NSUPDATE TCP response".to_string())?;

    super::xfr::wire::write_tcp_message(stream, &response)
        .await
        .map_err(|e| format!("Failed to write NSUPDATE TCP response: {}", e))
}

pub async fn handle_udp_nsupdate(
    socket: &UdpSocket,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), String> {
    log_info!("NSUPDATE UDP request from {}", client_addr);

    let rcode = handle_nsupdate_request(query_data, client_addr).await;
    let response = match build_response(query_data, rcode) {
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

async fn handle_nsupdate_request(query_data: &[u8], client_addr: SocketAddr) -> u8 {
    let parsed = match parser::parse_update_request(query_data) {
        Ok(req) => req,
        Err(e) => {
            log_warn!("NSUPDATE parse error from {}: {}", client_addr, e);
            return RCODE_FORMERR;
        }
    };

    match update::apply_update(parsed, query_data, client_addr).await {
        Ok(update::UpdateResult::Applied { changed }) => {
            log_info!(
                "NSUPDATE applied from {} (changed={})",
                client_addr,
                changed
            );
            RCODE_NOERROR
        }
        Err(update::UpdateError::Refused(msg)) => {
            log_warn!("NSUPDATE refused from {}: {}", client_addr, msg);
            RCODE_REFUSED
        }
        Err(update::UpdateError::YxDomain(msg)) => {
            log_warn!("NSUPDATE yxdomain from {}: {}", client_addr, msg);
            RCODE_YXDOMAIN
        }
        Err(update::UpdateError::YxRrset(msg)) => {
            log_warn!("NSUPDATE yxrrset from {}: {}", client_addr, msg);
            RCODE_YXRRSET
        }
        Err(update::UpdateError::NxDomain(msg)) => {
            log_warn!("NSUPDATE nxdomain from {}: {}", client_addr, msg);
            RCODE_NXDOMAIN
        }
        Err(update::UpdateError::NxRrset(msg)) => {
            log_warn!("NSUPDATE nxrrset from {}: {}", client_addr, msg);
            RCODE_NXRRSET
        }
        Err(update::UpdateError::NotZone(msg)) => {
            log_warn!("NSUPDATE notzone from {}: {}", client_addr, msg);
            RCODE_NOTZONE
        }
        Err(update::UpdateError::Internal(msg)) => {
            log_warn!("NSUPDATE internal error from {}: {}", client_addr, msg);
            RCODE_SERVFAIL
        }
    }
}

/// Returns the exclusive end offset of the first question/zone section within `message`,
/// measured from the start of the message buffer, or `None` if the message is malformed.
fn zone_section_end(message: &[u8]) -> Option<usize> {
    let mut offset = DNS_HEADER_LEN;

    // Parse QNAME: sequence of labels terminated by a zero-length label or
    // a two-byte compression pointer (top two bits set).
    loop {
        if offset >= message.len() {
            return None;
        }

        let len = message[offset];

        if (len & 0xC0) == 0xC0 {
            // Compression pointer – two bytes, name ends here.
            if offset + 1 >= message.len() {
                return None;
            }
            offset += 2;
            break;
        }

        if len == 0 {
            // End of QNAME.
            offset += 1;
            break;
        }

        // Regular label.
        offset += 1 + len as usize;
        if offset > message.len() {
            return None;
        }
    }

    // QTYPE (2 bytes) + QCLASS (2 bytes).
    if offset + 4 > message.len() {
        return None;
    }

    Some(offset + 4)
}

fn build_response(query_data: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query_data.len() < DNS_HEADER_LEN {
        return None;
    }

    let opcode_bits = query_data[2] & 0x78;
    let rd_bit = query_data[2] & 0x01;

    let qdcount = u16::from_be_bytes([query_data[4], query_data[5]]);
    let zone_end = if qdcount > 0 {
        zone_section_end(query_data)
    } else {
        None
    };

    let response_size = zone_end.unwrap_or(DNS_HEADER_LEN);
    let mut response = vec![0u8; response_size];

    // Transaction ID.
    response[0] = query_data[0];
    response[1] = query_data[1];

    // QR=1, preserve opcode and RD bit.
    response[2] = 0x80 | opcode_bits | rd_bit;
    // Preserve upper flag nibble, set RCODE in lower nibble.
    response[3] = (query_data[3] & 0xF0) | (rcode & 0x0F);

    if let Some(end) = zone_end {
        // QDCOUNT=1; ANCOUNT/NSCOUNT/ARCOUNT remain 0.
        response[4] = 0x00;
        response[5] = 0x01;
        // Copy the zone/question section verbatim from the query.
        response[DNS_HEADER_LEN..end].copy_from_slice(&query_data[DNS_HEADER_LEN..end]);
    }

    Some(response)
}
