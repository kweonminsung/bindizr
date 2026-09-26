//! When a committed change is propagated: the NOTIFY entry points and the
//! `dns.notify.batch_ms` choice between sending inline and queueing. The
//! batching worker lives in `queue`.

mod queue;

use bindizr_core::config;
pub use queue::{initialize_worker, stop_worker};

/// Send a DNS NOTIFY for `zone_name`, or — with `None` — for every zone,
/// aggregating per-zone failures. Enumerating the zones is this layer's
/// call, not the client's.
pub async fn send_notify(zone_name: Option<&str>) -> Result<(), String> {
    let Some(zone_name) = zone_name else {
        let zones = crate::zone::ZoneService::list()
            .await
            .map_err(|e| e.to_string())?;
        let mut failures = Vec::new();
        for zone in zones {
            if let Err(e) = crate::dns_client::notify::send_zone_notify(zone.name.as_str()).await {
                log::warn!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
                failures.push(format!("{}: {}", zone.name, e));
            }
        }
        return if failures.is_empty() {
            Ok(())
        } else {
            Err(format!("NOTIFY failed for {}", failures.join("; ")))
        };
    };
    crate::dns_client::notify::send_zone_notify(zone_name).await
}

/// NOTIFY the secondaries after a zone update: queued when `dns.notify.batch_ms`
/// sets a window, otherwise sent inline before the write is answered. The write
/// has committed, so a failure is logged rather than reported.
pub(crate) async fn notify_after_update(zone_name: &str) {
    let dns = &config::bindizr_config().dns;
    if dns.notify.batch_ms > 0 && queue::enqueue_notify(Some(zone_name)) {
        return;
    }

    if let Err(e) = send_notify(Some(zone_name)).await {
        log::warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
    }
}
