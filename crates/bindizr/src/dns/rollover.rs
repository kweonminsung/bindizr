//! The parent-DS poll that promotes rollovers unattended.

use std::sync::OnceLock;

use bindizr_core::{config::bindizr_config, log_error, log_info, log_warn};
use bindizr_service::{authorization::Caller, dnssec::DnssecService};

use crate::dns::client::probe;

/// Poll tick; day-scale DS TTLs make anything faster pointless.
const DS_POLL_INTERVAL_SECS: u64 = 3600;

static DS_POLL_SCHEDULER: OnceLock<()> = OnceLock::new();

/// Start the parent-DS poll when `dnssec.parent_ds_auto_promote` is on. Called once
/// from the daemon; later calls are no-ops.
pub(crate) fn init_ds_poll_scheduler() {
    if !bindizr_config().dnssec.parent_ds_auto_promote || DS_POLL_SCHEDULER.set(()).is_err() {
        return;
    }

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(DS_POLL_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            run_ds_poll_pass().await;
        }
    });
}

/// One poll pass: ask the resolver for each rolling zone's DS RRset and let
/// the service stamp observations and promote what is ready.
async fn run_ds_poll_pass() {
    let caller = Caller::Global;
    let zones = match DnssecService::list_zone_names_with_pending_parent_ds(&caller).await {
        Ok(zones) => zones,
        Err(e) => {
            log_error!("Parent-DS poll scan failed: {}", e);
            return;
        }
    };

    for zone_name in zones {
        let seen = match probe::probe_parent_ds(&zone_name).await {
            Ok(seen) => seen,
            Err(e) => {
                log_warn!("Parent-DS probe for zone {} failed: {}", zone_name, e);
                continue;
            }
        };
        match DnssecService::note_parent_ds_observed(&caller, &zone_name, &seen).await {
            Ok(Some(_)) => {
                log_info!(
                    "Promoted zone {} rollover after its parent DS was seen",
                    zone_name
                )
            }
            Ok(None) => {}
            Err(e) => log_error!("Parent-DS poll for zone {} failed: {}", zone_name, e),
        }
    }
}
