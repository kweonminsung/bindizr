use std::{net::SocketAddr, time::Duration};

use bindizr_core::dns::is_catalog_zone;
use domain::base::{
    Name,
    iana::{Opcode, Rcode},
};

use crate::{config, error::XfrError, log_error, log_info, service::zone::ZoneService, wire};

/// Sends DNS NOTIFY to all configured secondary servers.
/// A `None` zone_name notifies all zones; `force` bumps the target serial first.
pub async fn send_notify(zone_name: Option<&str>, force: bool) -> Result<(), XfrError> {
    if force {
        force_increment_serial(zone_name).await?;
    }

    match zone_name {
        Some(name) => send_notify_for_zone(name).await,
        None => send_notify_for_all_zones().await,
    }
}

async fn force_increment_serial(zone_name: Option<&str>) -> Result<(), XfrError> {
    if matches!(zone_name, Some(name) if is_catalog_zone(name)) {
        log_info!("Skipping forced serial increment for virtual catalog zone");
        return Ok(());
    }

    let bumped_zones = ZoneService::force_increment_serial(zone_name)
        .await
        .map_err(|e| {
            if e.code == crate::service::error::ErrorCode::ZoneNotFound {
                XfrError::ZoneNotFound(zone_name.unwrap_or_default().to_string())
            } else {
                XfrError::DatabaseError(e.to_string())
            }
        })?;

    log_info!(
        "Forced serial increment for {} zone(s) before NOTIFY",
        bumped_zones.len()
    );

    Ok(())
}

/// Sends DNS NOTIFY for every zone.
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

/// Sends DNS NOTIFY to all configured secondary servers for one zone.
async fn send_notify_for_zone(zone_name: &str) -> Result<(), XfrError> {
    log_info!("Sending NOTIFY for zone: {}", zone_name);

    if !is_catalog_zone(zone_name) {
        ZoneService::find(zone_name)
            .await
            .map_err(|e| XfrError::DatabaseError(e.to_string()))?
            .ok_or_else(|| XfrError::ZoneNotFound(zone_name.to_string()))?;
    }

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

    let notify_config = &config::get_bindizr_config().dns;
    let notify_timeout = Duration::from_secs(notify_config.notify_timeout_secs);
    let notify_retries = notify_config.notify_retries;

    let mut zone_name_bytes = Vec::new();
    wire::encode_domain_name(zone_name, &mut zone_name_bytes)?;
    let qname = Name::from_octets(zone_name_bytes)
        .map_err(|e| XfrError::ProtocolError(format!("Invalid zone name: {}", e)))?;

    for server_addr in server_addresses {
        match send_notify_to_server(&qname, server_addr, notify_timeout, notify_retries).await {
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

    for (entry, result) in super::resolve_secondary_entries(raw).await {
        match result {
            Ok(resolved) => addrs.extend(resolved),
            Err(e) => failures.push(format!("{}: {}", entry, e)),
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

/// Sends a NOTIFY to one server, retrying up to the configured limit.
async fn send_notify_to_server(
    zone_name: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
    retries: u32,
) -> Result<(), XfrError> {
    let attempts = retries.saturating_add(1);
    let mut last_error = None;

    for attempt in 1..=attempts {
        match send_notify_to_server_once(zone_name, server_addr, timeout).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt < attempts {
                    log_info!(
                        "Retrying NOTIFY to {} ({}/{}) after error: {}",
                        server_addr,
                        attempt + 1,
                        attempts,
                        e
                    );
                }
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        XfrError::ProtocolError(format!("NOTIFY to {} was not attempted", server_addr))
    }))
}

async fn send_notify_to_server_once(
    zone_name: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<(), XfrError> {
    let (query_id, notify_message) = super::build_question(Opcode::NOTIFY, true, zone_name)?;

    let (received, response) =
        super::udp_exchange(server_addr, timeout, &notify_message, "NOTIFY").await?;

    log_info!(
        "NOTIFY message sent to {} ({} bytes)",
        server_addr,
        notify_message.len()
    );

    validate_notify_response(query_id, &response[..received])?;

    Ok(())
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
mod tests;
