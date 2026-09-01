//! ds-seen with its assertion checked against the configured resolver, and
//! the poll that runs the same confirmation unattended. One home shared by
//! the HTTP API and the daemon socket.

use std::sync::OnceLock;

use bindizr_core::{config::bindizr_config, log_error, log_info, log_warn};
use bindizr_service::{
    authorization::Caller, dnssec::DnssecService, error::ServiceError,
    types::GetDnssecStatusResponse,
};

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

/// Verify the pending DS records at the resolver (unless `force`, or no
/// resolver is configured), then advance the rollover.
pub(crate) async fn confirm_ds_seen(
    caller: &Caller,
    zone_name: &str,
    force: bool,
) -> Result<GetDnssecStatusResponse, ServiceError> {
    let resolver = bindizr_config()
        .dnssec
        .parent_ds_resolver
        .trim()
        .to_string();
    if !force && !resolver.is_empty() {
        verify_parent_ds(caller, zone_name, &resolver).await?;
    }
    DnssecService::rollover_ds_seen(caller, zone_name).await
}

/// Every DS the pending keys need must be visible at the resolver; an absent
/// one would make the zone bogus for validators once the key signs.
async fn verify_parent_ds(
    caller: &Caller,
    zone_name: &str,
    resolver: &str,
) -> Result<(), ServiceError> {
    let expected = DnssecService::list_pending_parent_ds(caller, zone_name).await?;
    if expected.is_empty() {
        // No pending SEP key; rollover_ds_seen reports the precise state.
        return Ok(());
    }

    let seen = probe::probe_parent_ds(zone_name).await.map_err(|e| {
        ServiceError::invalid_input(format!(
            "could not verify the parent DS at {}: {}; pass force to skip this check",
            resolver, e
        ))
    })?;

    for ds in &expected {
        let visible = seen.iter().any(|answer| ds.matches(answer));
        if !visible {
            return Err(ServiceError::invalid_input(format!(
                "DS for key tag {} is not visible at {}; publish it at the parent and wait \
                 out the parent DS TTL, or pass force to skip this check",
                ds.key_tag, resolver
            )));
        }
    }
    Ok(())
}
