use std::{net::SocketAddr, str::FromStr, time::Duration};

use bindizr_core::{
    config,
    dns::{
        message::{Name, Opcode, Rtype},
        query::validate_notify_response,
    },
    metrics::{NotifyResult, track_notify},
};

use crate::secondary::SecondaryService;

/// Sends DNS NOTIFY to every enabled secondary for one zone. Which
/// zones to notify is the caller's decision.
pub(crate) async fn send_zone_notify(zone_name: &str) -> Result<(), String> {
    log::info!("Sending NOTIFY for zone: {}", zone_name);

    let reports = send_notify_to_secondaries(zone_name).await?;
    if reports.is_empty() {
        log::info!("No enabled secondaries");
        return Ok(());
    }

    let failures: Vec<String> = reports
        .iter()
        .filter_map(|report| {
            report
                .result
                .as_ref()
                .err()
                .map(|e| format!("{}: {}", report.address, e))
        })
        .collect();

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "NOTIFY failed for zone {} ({})",
            zone_name,
            failures.join("; ")
        ))
    }
}

/// One secondary's NOTIFY outcome.
pub struct NotifyReport {
    pub address: String,
    pub result: Result<(), String>,
}

/// Send NOTIFY for a zone to every resolved address of every enabled
/// secondary (the transfer ACL admits each one, so every replica must hear
/// the change). No enabled secondary yields an empty list.
pub async fn send_notify_to_secondaries(zone_name: &str) -> Result<Vec<NotifyReport>, String> {
    let secondaries = SecondaryService::list_enabled()
        .await
        .map_err(|e| e.to_string())?;
    if secondaries.is_empty() {
        return Ok(Vec::new());
    }
    let dns_config = &config::bindizr_config().dns;
    let timeout = Duration::from_secs(dns_config.notify.timeout_secs);
    let retries = dns_config.notify.retries;

    let qname =
        Name::<Vec<u8>>::from_str(zone_name).map_err(|e| format!("Invalid zone name: {}", e))?;

    let mut reports = Vec::new();
    for secondary in secondaries {
        let addrs = match super::resolve_address_entry(&secondary.address, timeout).await {
            Ok(addrs) => addrs,
            Err(e) => {
                track_notify(NotifyResult::ResolveError);
                reports.push(NotifyReport {
                    address: secondary.address,
                    result: Err(format!("failed to resolve: {}", e)),
                });
                continue;
            }
        };

        for addr in addrs {
            let result = match send_notify_to_server(&qname, addr, timeout, retries).await {
                Ok(()) => {
                    log::info!("NOTIFY sent successfully to {}", addr);
                    track_notify(NotifyResult::Ok);
                    Ok(())
                }
                Err(e) => {
                    log::error!("Failed to send NOTIFY to {}: {}", addr, e);
                    track_notify(NotifyResult::Error);
                    Err(e)
                }
            };
            reports.push(NotifyReport {
                address: addr.to_string(),
                result,
            });
        }
    }

    Ok(reports)
}

/// Sends a NOTIFY to one server, retrying up to the configured limit.
async fn send_notify_to_server(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
    retries: u32,
) -> Result<(), String> {
    let attempts = retries.saturating_add(1);
    let mut last_error = None;

    for attempt in 1..=attempts {
        match send_notify_to_server_once(qname, server_addr, timeout).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt < attempts {
                    log::info!(
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

    Err(last_error.unwrap_or_else(|| format!("NOTIFY to {} was not attempted", server_addr)))
}

/// Send one NOTIFY attempt and validate the server's response.
async fn send_notify_to_server_once(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<(), String> {
    let (query_id, notify_message) =
        bindizr_core::dns::query::build_question(Opcode::NOTIFY, true, false, qname, Rtype::SOA);

    let (received, response) =
        super::exchange_over_udp(server_addr, timeout, &notify_message, "NOTIFY").await?;

    log::info!(
        "NOTIFY message sent to {} ({} bytes)",
        server_addr,
        notify_message.len()
    );

    validate_notify_response(query_id, qname, &response[..received])?;

    Ok(())
}

#[cfg(test)]
mod tests;
