//! ds-seen with its assertion checked against the configured resolver.
//! One home shared by the HTTP API and the daemon socket.

use bindizr_core::config::bindizr_config;
use bindizr_service::{
    authorization::Caller, dnssec::DnssecService, error::ServiceError,
    types::GetDnssecStatusResponse,
};

use crate::dns::client::probe;

/// Verify the pending DS records at the resolver (unless `force`, or no
/// resolver is configured), then advance the rollover.
pub(crate) async fn confirm_ds_seen(
    caller: &Caller,
    zone_name: &str,
    force: bool,
) -> Result<GetDnssecStatusResponse, ServiceError> {
    let resolver = bindizr_config().dnssec.ds_probe_resolver.trim().to_string();
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
        let visible = seen.iter().any(|answer| {
            i32::from(answer.key_tag) == ds.key_tag
                && answer.algorithm == ds.algorithm
                && answer.digest_type == ds.digest_type
                && answer.digest == ds.digest
        });
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
