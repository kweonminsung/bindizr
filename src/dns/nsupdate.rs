use crate::{log_info, log_warn};
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};

const DNS_HEADER_LEN: usize = 12;
const DNS_OPCODE_UPDATE: u8 = 5;
const DNS_RCODE_NOTIMP: u8 = 4;

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

    let response = build_not_implemented_response(query_data)
        .ok_or_else(|| "Invalid NSUPDATE query header".to_string())?;

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

    let response = match build_not_implemented_response(query_data) {
        Some(response) => response,
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

fn build_not_implemented_response(query_data: &[u8]) -> Option<Vec<u8>> {
    if query_data.len() < DNS_HEADER_LEN {
        return None;
    }

    let mut response = vec![0u8; DNS_HEADER_LEN];

    response[0] = query_data[0];
    response[1] = query_data[1];

    let opcode_bits = query_data[2] & 0x78;
    let rd_bit = query_data[2] & 0x01;
    response[2] = 0x80 | opcode_bits | rd_bit;
    response[3] = (query_data[3] & 0xF0) | DNS_RCODE_NOTIMP;

    Some(response)
}