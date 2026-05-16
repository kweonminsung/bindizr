use super::{error::XfrError, wire};
use crate::{config, log_error, log_info, service::zone::ZoneService};
use domain::base::{
    Name, Rtype, StaticCompressor,
    iana::{Opcode, Rcode},
    message_builder::MessageBuilder,
};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Send DNS NOTIFY to all configured DNS servers for a zone
/// If zone_name is None, sends NOTIFY for all zones
pub async fn send_notify(zone_name: Option<&str>) -> Result<(), XfrError> {
    match zone_name {
        Some(name) => send_notify_for_zone(name).await,
        None => send_notify_for_all_zones().await,
    }
}

/// Send DNS NOTIFY for all zones
async fn send_notify_for_all_zones() -> Result<(), XfrError> {
    log_info!("Sending NOTIFY for all zones");

    let zones = ZoneService::list()
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    if zones.is_empty() {
        log_info!("No zones found");
        return Ok(());
    }

    log_info!("Found {} zone(s) to notify", zones.len());

    for zone in zones {
        log_info!("Processing NOTIFY for zone: {}", zone.name);
        if let Err(e) = send_notify_for_zone(&zone.name).await {
            log_error!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
        }
    }

    Ok(())
}

/// Send DNS NOTIFY to all configured DNS servers for a specific zone
async fn send_notify_for_zone(zone_name: &str) -> Result<(), XfrError> {
    log_info!("Sending NOTIFY for zone: {}", zone_name);

    // Verify zone exists
    ZoneService::find(zone_name)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name.to_string()))?;

    // Get secondary servers from config (comma-separated list)
    let secondary_servers_str: String = config::get_config("dns.secondary_addrs");
    if secondary_servers_str.is_empty() {
        log_info!("No secondary DNS servers configured");
        return Ok(());
    }

    // Parse secondary servers list (format: "ip:port,ip:port,...")
    let server_addresses: Vec<SocketAddr> = secondary_servers_str
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            match trimmed.parse::<SocketAddr>() {
                Ok(addr) => Some(addr),
                Err(e) => {
                    log_error!("Invalid server address '{}': {}", trimmed, e);
                    None
                }
            }
        })
        .collect();

    if server_addresses.is_empty() {
        log_info!("No valid secondary DNS servers found in config");
        return Ok(());
    }

    log_info!(
        "Sending NOTIFY to {} secondary DNS server(s) for zone {}",
        server_addresses.len(),
        zone_name
    );

    // Parse zone name - encode to DNS wire format
    let mut zone_name_bytes = Vec::new();
    wire::encode_domain_name(zone_name, &mut zone_name_bytes)?;
    let qname = Name::from_octets(zone_name_bytes)
        .map_err(|e| XfrError::ProtocolError(format!("Invalid zone name: {}", e)))?;

    // Send NOTIFY to each secondary DNS server
    for server_addr in server_addresses {
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

    // Bind to appropriate address based on target
    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(XfrError::IoError)?;

    // Send NOTIFY with timeout
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.send_to(&notify_message, server_addr),
    )
    .await
    .map_err(|_| XfrError::ProtocolError("NOTIFY send timeout".to_string()))?
    .map_err(XfrError::IoError)?;

    log_info!(
        "NOTIFY message sent to {} ({} bytes)",
        server_addr,
        notify_message.len()
    );

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
