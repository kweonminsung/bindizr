use std::{net::SocketAddr, str::FromStr, time::Duration};

use bindizr_core::{
    config,
    dns::{
        message::{Name, Opcode, Rtype},
        query::validate_notify_response,
    },
    log_error, log_info,
    metrics::metrics,
};

/// Sends DNS NOTIFY to all configured secondary servers for one zone. Which
/// zones to notify is the caller's decision.
pub async fn send_notify(zone_name: &str) -> Result<(), String> {
    log_info!("Sending NOTIFY for zone: {}", zone_name);

    let reports = notify_secondaries(zone_name).await?;
    if reports.is_empty() {
        log_info!("No secondary DNS servers configured");
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

/// One configured secondary's NOTIFY outcome.
pub struct NotifyReport {
    pub address: String,
    pub result: Result<(), String>,
}

/// Send NOTIFY for a zone to every resolved secondary address (the transfer
/// ACL admits each one, so every replica must hear the change). An empty
/// `secondary_addrs` yields an empty list.
pub async fn notify_secondaries(zone_name: &str) -> Result<Vec<NotifyReport>, String> {
    let dns_config = &config::bindizr_config().dns;
    let raw = dns_config.secondary_addrs.as_str();
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let timeout = Duration::from_secs(dns_config.notify_timeout_secs);
    let retries = dns_config.notify_retries;

    let qname =
        Name::<Vec<u8>>::from_str(zone_name).map_err(|e| format!("Invalid zone name: {}", e))?;

    let mut reports = Vec::new();
    for (entry, result) in super::resolve_secondary_entries(raw, timeout).await {
        let addrs = match result {
            Ok(addrs) => addrs,
            Err(e) => {
                // Nothing was sent, so resolution failures must not inflate
                // the send-failure rate.
                metrics()
                    .notify_sent_total
                    .with_label_values(&["resolve_error"])
                    .inc();
                reports.push(NotifyReport {
                    address: entry,
                    result: Err(format!("failed to resolve: {}", e)),
                });
                continue;
            }
        };

        for addr in addrs {
            let result = match send_notify_to_server(&qname, addr, timeout, retries).await {
                Ok(()) => {
                    log_info!("NOTIFY sent successfully to {}", addr);
                    metrics().notify_sent_total.with_label_values(&["ok"]).inc();
                    Ok(())
                }
                Err(e) => {
                    log_error!("Failed to send NOTIFY to {}: {}", addr, e);
                    metrics()
                        .notify_sent_total
                        .with_label_values(&["error"])
                        .inc();
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

    Err(last_error.unwrap_or_else(|| format!("NOTIFY to {} was not attempted", server_addr)))
}

async fn send_notify_to_server_once(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<(), String> {
    let (query_id, notify_message) =
        bindizr_core::dns::query::build_question(Opcode::NOTIFY, true, false, qname, Rtype::SOA);

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

#[cfg(test)]
mod tests;
