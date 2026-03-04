use super::error::XfrError;
use crate::{
    database::{get_dns_server_repository, get_zone_repository},
    log_error, log_info,
};
use domain::base::{
    Name, Rtype, StaticCompressor,
    iana::{Opcode, Rcode},
    message_builder::MessageBuilder,
};
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

/// Send DNS NOTIFY to all configured DNS servers for a zone
pub async fn send_notify(zone_name: &str) -> Result<(), XfrError> {
    log_info!("Sending NOTIFY for zone: {}", zone_name);

    // Verify zone exists
    let zone_repo = get_zone_repository();
    zone_repo
        .get_by_name(zone_name)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name.to_string()))?;

    // Get all DNS servers from dns_servers table
    let dns_server_repo = get_dns_server_repository();
    let dns_servers = dns_server_repo
        .get_all()
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    if dns_servers.is_empty() {
        log_info!("No DNS servers configured");
        return Ok(());
    }

    log_info!(
        "Sending NOTIFY to {} DNS server(s) for zone {}",
        dns_servers.len(),
        zone_name
    );

    // Parse zone name
    let zone_name_bytes = zone_name.as_bytes().to_vec();
    let qname = Name::from_octets(zone_name_bytes)
        .map_err(|e| XfrError::ProtocolError(format!("Invalid zone name: {}", e)))?;

    // Send NOTIFY to each DNS server
    for dns_server in dns_servers {
        let server_ip: IpAddr = match dns_server.ip_address.parse() {
            Ok(ip) => ip,
            Err(e) => {
                log_error!("Invalid IP address {}: {}", dns_server.ip_address, e);
                continue;
            }
        };

        let server_addr = SocketAddr::new(server_ip, dns_server.port as u16);

        match send_notify_to_server(&qname, server_addr).await {
            Ok(()) => {
                log_info!("NOTIFY sent successfully to {}", server_addr);
            }
            Err(e) => {
                log_error!("Failed to send NOTIFY to {}: {}", server_addr, e);
            }
        }
    }

    Ok(())
}

/// Send a single NOTIFY message to a server
async fn send_notify_to_server(
    zone_name: &Name<Vec<u8>>,
    server_addr: SocketAddr,
) -> Result<(), XfrError> {
    // Build NOTIFY message
    let notify_message = build_notify_message(zone_name)?;

    // Bind to any available port
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(XfrError::IoError)?;

    // Send NOTIFY
    socket
        .send_to(&notify_message, server_addr)
        .await
        .map_err(XfrError::IoError)?;

    log_info!("NOTIFY message sent to {}", server_addr);

    Ok(())
}

/// Build a DNS NOTIFY message (RFC 1996)
fn build_notify_message(zone_name: &Name<Vec<u8>>) -> Result<Vec<u8>, XfrError> {
    // Create message builder with random ID
    let query_id = rand::random::<u16>();
    let mut msg = MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
        .map_err(|e| XfrError::ProtocolError(format!("Failed to create message builder: {}", e)))?;

    // Set NOTIFY opcode (opcode = 4, AA flag set, QR flag clear)
    let header = msg.header_mut();
    header.set_id(query_id);
    header.set_opcode(Opcode::NOTIFY);
    header.set_aa(true); // Authoritative
    header.set_qr(false); // Query, not response
    header.set_rcode(Rcode::NOERROR);

    // Add question section (zone SOA)
    let mut question = msg.question();
    question
        .push((zone_name, Rtype::SOA))
        .map_err(|e| XfrError::ProtocolError(format!("Failed to add question: {}", e)))?;

    // Get answer section (but leave it empty)
    let answer = question.answer();

    let msg_bytes = answer.finish().into_target().as_slice().to_vec();

    Ok(msg_bytes)
}
