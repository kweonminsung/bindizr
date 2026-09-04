//! When a committed change is propagated: the NOTIFY entry points and the
//! `notify_after_update` gate. The batching worker lives in [`queue`].

mod queue;

use bindizr_core::config::{self, NotifyMode};
pub use queue::init_notify_worker;

use crate::log_warn;

/// Send a DNS NOTIFY for `zone_name`, or — with `None` — for every zone,
/// aggregating per-zone failures.
pub async fn send_notify(zone_name: Option<&str>) -> Result<(), String> {
    let Some(zone_name) = zone_name else {
        return send_notify_for_all_zones().await;
    };
    crate::dns_client::notify::send_notify(zone_name).await
}

/// Enumerating the zones is this layer's call, not the client's.
async fn send_notify_for_all_zones() -> Result<(), String> {
    let zones = crate::zone::ZoneService::list()
        .await
        .map_err(|e| e.to_string())?;
    if zones.is_empty() {
        return Ok(());
    }

    let mut failures = Vec::new();
    for zone in zones {
        if let Err(e) = crate::dns_client::notify::send_notify(zone.name.as_str()).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
            failures.push(format!("{}: {}", zone.name, e));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("NOTIFY failed for {}", failures.join("; ")))
    }
}

/// Send a NOTIFY after a zone update, unless disabled by `notify_after_update`.
/// In async mode it is queued and this returns at once; otherwise sent inline.
pub(crate) async fn send_notify_after_update(zone_name: Option<&str>) -> Result<(), String> {
    let dns = &config::bindizr_config().dns;
    if !dns.notify_after_update {
        return Ok(());
    }

    if dns.notify_mode == NotifyMode::Async && queue::enqueue_notify(zone_name) {
        return Ok(());
    }

    send_notify(zone_name).await
}
