mod auth;
mod parser;
mod prerequisite;
mod update;

use std::net::SocketAddr;

use tokio::net::{TcpStream, UdpSocket};
use update::TsigErrorResponse;

use crate::{
    log_info, log_warn,
    protocol::{
        CLASS_ANY, DNS_COMPRESSION_POINTER_MASK, DNS_HEADER_LEN, DNS_OPCODE_UPDATE, RCODE_FORMERR,
        RCODE_NOERROR, RCODE_NOTAUTH, RCODE_NOTZONE, RCODE_NXDOMAIN, RCODE_NXRRSET, RCODE_REFUSED,
        RCODE_SERVFAIL, RCODE_YXDOMAIN, RCODE_YXRRSET, TYPE_TSIG,
    },
};

struct NsupdateResponse {
    rcode: u8,
    tsig: Option<TsigErrorResponse>,
}

pub(crate) fn is_nsupdate(message: &[u8]) -> bool {
    if message.len() < DNS_HEADER_LEN {
        return false;
    }

    let opcode = (message[2] >> 3) & 0x0f;
    opcode == DNS_OPCODE_UPDATE
}

pub(crate) async fn handle_tcp_nsupdate(
    stream: &mut TcpStream,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), String> {
    log_info!("NSUPDATE TCP request from {}", client_addr);

    let result = handle_nsupdate_request(query_data, client_addr).await;
    let response = build_response(query_data, result)
        .ok_or_else(|| "Failed to build NSUPDATE TCP response".to_string())?;

    super::xfr::wire::write_tcp_message(stream, &response)
        .await
        .map_err(|e| format!("Failed to write NSUPDATE TCP response: {}", e))
}

pub(crate) async fn handle_udp_nsupdate(
    socket: &UdpSocket,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), String> {
    log_info!("NSUPDATE UDP request from {}", client_addr);

    let result = handle_nsupdate_request(query_data, client_addr).await;
    let response = match build_response(query_data, result) {
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

async fn handle_nsupdate_request(query_data: &[u8], client_addr: SocketAddr) -> NsupdateResponse {
    let parsed = match parser::parse_update_request(query_data) {
        Ok(req) => req,
        Err(e) => {
            log_warn!("NSUPDATE parse error from {}: {}", client_addr, e);
            return NsupdateResponse {
                rcode: RCODE_FORMERR,
                tsig: None,
            };
        }
    };

    match update::apply_update(parsed, query_data, client_addr).await {
        Ok(update::UpdateResult::Applied { changed }) => {
            log_info!(
                "NSUPDATE applied from {} (changed={})",
                client_addr,
                changed
            );
            NsupdateResponse {
                rcode: RCODE_NOERROR,
                tsig: None,
            }
        }
        Err(update::UpdateError::Refused(msg)) => {
            log_warn!("NSUPDATE refused from {}: {}", client_addr, msg);
            NsupdateResponse {
                rcode: RCODE_REFUSED,
                tsig: None,
            }
        }
        Err(update::UpdateError::NotAuth { msg, tsig }) => {
            log_warn!("NSUPDATE notauth from {}: {}", client_addr, msg);
            NsupdateResponse {
                rcode: RCODE_NOTAUTH,
                tsig,
            }
        }
        Err(update::UpdateError::YxDomain(msg)) => {
            log_warn!("NSUPDATE yxdomain from {}: {}", client_addr, msg);
            NsupdateResponse {
                rcode: RCODE_YXDOMAIN,
                tsig: None,
            }
        }
        Err(update::UpdateError::YxRrset(msg)) => {
            log_warn!("NSUPDATE yxrrset from {}: {}", client_addr, msg);
            NsupdateResponse {
                rcode: RCODE_YXRRSET,
                tsig: None,
            }
        }
        Err(update::UpdateError::NxDomain(msg)) => {
            log_warn!("NSUPDATE nxdomain from {}: {}", client_addr, msg);
            NsupdateResponse {
                rcode: RCODE_NXDOMAIN,
                tsig: None,
            }
        }
        Err(update::UpdateError::NxRrset(msg)) => {
            log_warn!("NSUPDATE nxrrset from {}: {}", client_addr, msg);
            NsupdateResponse {
                rcode: RCODE_NXRRSET,
                tsig: None,
            }
        }
        Err(update::UpdateError::NotZone(msg)) => {
            log_warn!("NSUPDATE notzone from {}: {}", client_addr, msg);
            NsupdateResponse {
                rcode: RCODE_NOTZONE,
                tsig: None,
            }
        }
        Err(update::UpdateError::Internal(msg)) => {
            log_warn!("NSUPDATE internal error from {}: {}", client_addr, msg);
            NsupdateResponse {
                rcode: RCODE_SERVFAIL,
                tsig: None,
            }
        }
    }
}

/// Returns the end offset of the first question (zone) section, or None if the message is invalid
fn zone_section_end(message: &[u8]) -> Option<usize> {
    let mut offset = DNS_HEADER_LEN;

    // Parse QNAME: labels ending with 0 or a compression pointer (2 bytes)
    loop {
        if offset >= message.len() {
            return None;
        }

        let len = message[offset];

        if (len & DNS_COMPRESSION_POINTER_MASK) == DNS_COMPRESSION_POINTER_MASK {
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

fn build_response(query_data: &[u8], result: NsupdateResponse) -> Option<Vec<u8>> {
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
    response[3] = (query_data[3] & 0xF0) | (result.rcode & 0x0F);

    if let Some(end) = zone_end {
        // QDCOUNT=1; ANCOUNT/NSCOUNT/ARCOUNT remain 0.
        response[4] = 0x00;
        response[5] = 0x01;
        // Copy the zone/question section verbatim from the query.
        response[DNS_HEADER_LEN..end].copy_from_slice(&query_data[DNS_HEADER_LEN..end]);
    }

    if let Some(tsig) = result.tsig {
        append_tsig_error(&mut response, &tsig)?;
        response[10..12].copy_from_slice(&1u16.to_be_bytes());
    }

    Some(response)
}

fn append_tsig_error(response: &mut Vec<u8>, tsig: &TsigErrorResponse) -> Option<()> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&tsig.algorithm_canonical);
    rdata.extend_from_slice(&encode_u48(tsig.time_signed));
    rdata.extend_from_slice(&tsig.fudge.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes());
    rdata.extend_from_slice(&tsig.original_id.to_be_bytes());
    rdata.extend_from_slice(&tsig.error.to_be_bytes());
    rdata.extend_from_slice(&(u16::try_from(tsig.other_data.len()).ok()?).to_be_bytes());
    rdata.extend_from_slice(&tsig.other_data);

    response.extend_from_slice(&tsig.name_canonical);
    response.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    response.extend_from_slice(&CLASS_ANY.to_be_bytes());
    response.extend_from_slice(&0u32.to_be_bytes());
    response.extend_from_slice(&(u16::try_from(rdata.len()).ok()?).to_be_bytes());
    response.extend_from_slice(&rdata);

    Some(())
}

fn encode_u48(value: u64) -> [u8; 6] {
    [
        ((value >> 40) & 0xff) as u8,
        ((value >> 32) & 0xff) as u8,
        ((value >> 24) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ]
}

#[cfg(test)]
mod tests;
