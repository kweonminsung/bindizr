use super::{catalog, error::XfrError, wire};
use crate::{config, log_error, log_info, service::zone::ZoneService};
use domain::base::{
    Name, Rtype, StaticCompressor,
    iana::{Opcode, Rcode},
    message_builder::MessageBuilder,
};
use std::net::SocketAddr;
use tokio::net::{UdpSocket, lookup_host};

const NOTIFY_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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

    let mut failures = Vec::new();

    for zone in zones {
        log_info!("Processing NOTIFY for zone: {}", zone.name);
        if let Err(e) = send_notify_for_zone(&zone.name).await {
            log_error!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
            failures.push(format!("{}: {}", zone.name, e));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(XfrError::NotifyFailed(failures.join("; ")))
    }
}

/// Send DNS NOTIFY to all configured DNS servers for a specific zone
async fn send_notify_for_zone(zone_name: &str) -> Result<(), XfrError> {
    log_info!("Sending NOTIFY for zone: {}", zone_name);

    if !catalog::is_catalog_zone(zone_name) {
        // Verify zone exists
        ZoneService::find(zone_name)
            .await
            .map_err(|e| XfrError::DatabaseError(e.to_string()))?
            .ok_or_else(|| XfrError::ZoneNotFound(zone_name.to_string()))?;
    }

    // Get secondary servers from config (comma-separated list)
    let secondary_servers_str = &config::get_bindizr_config().dns.secondary_addrs;
    if secondary_servers_str.trim().is_empty() {
        log_info!("No secondary DNS servers configured");
        return Ok(());
    }

    let (server_addresses, mut failures) = resolve_secondary_servers(secondary_servers_str).await;

    if server_addresses.is_empty() {
        return Err(XfrError::NotifyFailed(format!(
            "No valid secondary DNS servers found in config{}",
            format_failures(&failures)
        )));
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
                failures.push(format!("{}: {}", server_addr, e));
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(XfrError::NotifyFailed(format!(
            "zone {}{}",
            zone_name,
            format_failures(&failures)
        )))
    }
}

async fn resolve_secondary_servers(raw: &str) -> (Vec<SocketAddr>, Vec<String>) {
    let mut addrs = Vec::new();
    let mut failures = Vec::new();

    for item in raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        match lookup_host(trimmed).await {
            Ok(resolved) => addrs.extend(resolved),
            Err(e) => {
                log_error!("Invalid server address '{}': {}", trimmed, e);
                failures.push(format!("{}: {}", trimmed, e));
            }
        }
    }

    (addrs, failures)
}

fn format_failures(failures: &[String]) -> String {
    if failures.is_empty() {
        String::new()
    } else {
        format!(" ({})", failures.join("; "))
    }
}

/// Send a single NOTIFY message to a server
async fn send_notify_to_server(
    zone_name: &Name<Vec<u8>>,
    server_addr: SocketAddr,
) -> Result<(), XfrError> {
    // Build NOTIFY message
    let (query_id, notify_message) = build_notify_message(zone_name)?;

    // Bind to appropriate address based on target
    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(XfrError::IoError)?;
    socket
        .connect(server_addr)
        .await
        .map_err(XfrError::IoError)?;

    // Send NOTIFY with timeout
    let sent = tokio::time::timeout(NOTIFY_RESPONSE_TIMEOUT, socket.send(&notify_message))
        .await
        .map_err(|_| XfrError::ProtocolError("NOTIFY send timeout".to_string()))?
        .map_err(XfrError::IoError)?;

    if sent != notify_message.len() {
        return Err(XfrError::ProtocolError(format!(
            "Incomplete NOTIFY send to {}: sent {} of {} bytes",
            server_addr,
            sent,
            notify_message.len()
        )));
    }

    log_info!(
        "NOTIFY message sent to {} ({} bytes)",
        server_addr,
        notify_message.len()
    );

    let mut response = [0u8; 512];
    let received = tokio::time::timeout(NOTIFY_RESPONSE_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| {
            XfrError::ProtocolError(format!("NOTIFY response timeout from {}", server_addr))
        })?
        .map_err(XfrError::IoError)?;

    validate_notify_response(query_id, &response[..received])?;

    Ok(())
}

/// Build a DNS NOTIFY message (RFC 1996)
fn build_notify_message(zone_name: &Name<Vec<u8>>) -> Result<(u16, Vec<u8>), XfrError> {
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

    Ok((query_id, msg_bytes))
}

fn validate_notify_response(query_id: u16, response: &[u8]) -> Result<(), XfrError> {
    if response.len() < 12 {
        return Err(XfrError::ProtocolError(format!(
            "NOTIFY response is too short: {} bytes",
            response.len()
        )));
    }

    let response_id = u16::from_be_bytes([response[0], response[1]]);
    if response_id != query_id {
        return Err(XfrError::ProtocolError(format!(
            "NOTIFY response ID mismatch: expected {}, got {}",
            query_id, response_id
        )));
    }

    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err(XfrError::ProtocolError(
            "NOTIFY response does not have QR bit set".to_string(),
        ));
    }

    let opcode = (flags >> 11) & 0x0f;
    if opcode != Opcode::NOTIFY.to_int() as u16 {
        return Err(XfrError::ProtocolError(format!(
            "NOTIFY response opcode mismatch: expected {}, got {}",
            Opcode::NOTIFY.to_int(),
            opcode
        )));
    }

    let rcode = flags & 0x0f;
    if rcode != Rcode::NOERROR.to_int() as u16 {
        return Err(XfrError::ProtocolError(format!(
            "NOTIFY response returned RCODE {}",
            rcode
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notify_response(query_id: u16, flags: u16) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&query_id.to_be_bytes());
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response
    }

    #[test]
    fn validate_notify_response_accepts_matching_noerror_response() {
        let response = notify_response(1234, 0xa000);

        assert!(validate_notify_response(1234, &response).is_ok());
    }

    #[test]
    fn validate_notify_response_rejects_id_mismatch() {
        let response = notify_response(1234, 0xa000);

        let err = validate_notify_response(5678, &response).unwrap_err();

        assert!(err.to_string().contains("ID mismatch"));
    }

    #[test]
    fn validate_notify_response_rejects_error_rcode() {
        let response = notify_response(1234, 0xa005);

        let err = validate_notify_response(1234, &response).unwrap_err();

        assert!(err.to_string().contains("RCODE 5"));
    }
}
