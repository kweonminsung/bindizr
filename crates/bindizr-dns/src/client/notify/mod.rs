use std::{net::SocketAddr, str::FromStr, time::Duration};

use bindizr_core::dns::is_catalog_zone;
use domain::base::{
    Message, Name,
    iana::{Opcode, Rcode},
};

use crate::{config, error::XfrError, log_error, log_info, service::zone::ZoneService};

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

    let qname = Name::<Vec<u8>>::from_str(zone_name)
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

/// One configured secondary's NOTIFY outcome.
pub struct SecondaryNotify {
    pub address: String,
    pub result: Result<(), String>,
}

/// Send NOTIFY for a zone to every configured secondary, reporting each
/// entry's outcome instead of collapsing failures into one error. An empty
/// `secondary_addrs` yields an empty list.
pub async fn notify_secondaries(zone_name: &str) -> Result<Vec<SecondaryNotify>, XfrError> {
    let dns_config = &config::get_bindizr_config().dns;
    let raw = dns_config.secondary_addrs.clone();
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let timeout = Duration::from_secs(dns_config.notify_timeout_secs);
    let retries = dns_config.notify_retries;

    let qname = Name::<Vec<u8>>::from_str(zone_name)
        .map_err(|e| XfrError::ProtocolError(format!("Invalid zone name: {}", e)))?;

    let mut reports = Vec::new();
    for (entry, result) in super::resolve_secondary_entries(&raw).await {
        let addrs = match result {
            Ok(addrs) => addrs,
            Err(e) => {
                reports.push(SecondaryNotify {
                    address: entry,
                    result: Err(format!("failed to resolve: {}", e)),
                });
                continue;
            }
        };

        let mut last = None;
        for addr in addrs {
            match send_notify_to_server(&qname, addr, timeout, retries).await {
                Ok(()) => {
                    last = Some((addr.to_string(), Ok(())));
                    break;
                }
                Err(e) => last = Some((addr.to_string(), Err(e.to_string()))),
            }
        }

        let (address, result) = last.expect("resolve_secondary_entries never yields an empty Ok");
        reports.push(SecondaryNotify { address, result });
    }

    Ok(reports)
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
    let (query_id, notify_message) = super::build_question(Opcode::NOTIFY, true, zone_name);

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
    let message = Message::from_octets(response)
        .map_err(|e| XfrError::ProtocolError(format!("NOTIFY response is malformed: {}", e)))?;

    let header = message.header();
    if header.id() != query_id {
        return Err(XfrError::ProtocolError(format!(
            "NOTIFY response ID mismatch: expected {}, got {}",
            query_id,
            header.id()
        )));
    }

    if !header.qr() {
        return Err(XfrError::ProtocolError(
            "NOTIFY response does not have QR bit set".to_string(),
        ));
    }

    if header.opcode() != Opcode::NOTIFY {
        return Err(XfrError::ProtocolError(format!(
            "NOTIFY response opcode mismatch: expected {}, got {}",
            Opcode::NOTIFY.to_int(),
            header.opcode().to_int()
        )));
    }

    if header.rcode() != Rcode::NOERROR {
        return Err(XfrError::ProtocolError(format!(
            "NOTIFY response returned RCODE {}",
            header.rcode().to_int()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
