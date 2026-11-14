//! Read the transfer log rows matching a secondary's current addresses.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use bindizr_core::model::role_grant::Action;
use bindizr_core::model::secondary::Secondary;
use bindizr_core::model::transfer::{TransferKind, TransferLogWithZone, TransferResult};
use bindizr_db::transfer_log::TransferLogFilter;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::{
    SecondaryTransferFilter, SecondaryTransfersResponse, TransferResponse, TransferSummaryResponse,
};
use crate::{Context, dns_client, pagination, transfer, zone};

/// List the transfers Bindizr answered `name`, newest first, with how each zone
/// was last served.
pub async fn list_transfers(
    cx: &Context,
    caller: &Caller,
    name: &str,
    filter: &SecondaryTransferFilter,
) -> Result<SecondaryTransfersResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryRead)?;
    let limit = filter.limit.unwrap_or(1000);
    pagination::validate_page_limit(Some(limit))?;

    if let (Some(since), Some(until)) = (filter.since, filter.until)
        && since >= until
    {
        return Err(ServiceError::invalid_input("since must be before until"));
    }

    let secondary = super::lookup_by_name(cx, name).await?;

    let zone_name = filter
        .zone_name
        .as_deref()
        .map(zone::normalize_name)
        .transpose()?;

    // The summary counts every zone's last transfer, whatever the filter selects.
    let client_ips = resolve_ips(cx, &secondary).await;
    let latest = transfer::list_latest_by_clients(cx, &client_ips).await?;
    let logs = transfer::list_by_clients(
        cx,
        &client_ips,
        &TransferLogFilter {
            zone_name,
            since: filter.since,
            until: filter.until,
            limit: Some(limit),
        },
    )
    .await?;

    Ok(SecondaryTransfersResponse {
        secondary_name: secondary.name,
        address: secondary.address.to_string(),
        summary: build_transfer_summary(&latest),
        transfers: logs.iter().map(TransferResponse::from).collect(),
    })
}

/// Summarize how Bindizr last served `secondary` each zone, for the check and doctor.
pub(crate) async fn summarize_transfers(
    cx: &Context,
    secondary: &Secondary,
) -> Result<TransferSummaryResponse, ServiceError> {
    let latest = transfer::list_latest_by_clients(cx, &resolve_ips(cx, secondary).await).await?;
    Ok(build_transfer_summary(&latest))
}

/// Count each zone by its latest transfer among `logs`.
fn build_transfer_summary(logs: &[TransferLogWithZone]) -> TransferSummaryResponse {
    let mut latest: HashMap<&str, &TransferLogWithZone> = HashMap::new();

    for log in logs {
        let entry = latest.entry(log.zone_name.as_str()).or_insert(log);
        if log.served_at > entry.served_at {
            *entry = log;
        }
    }

    let mut summary = TransferSummaryResponse {
        zones: latest.len() as u64,
        axfr: 0,
        ixfr_full: 0,
        ixfr_delta: 0,
        refused: 0,
        failed: 0,
    };

    for log in latest.values() {
        match (log.result, log.kind, log.incremental) {
            (TransferResult::Refused, _, _) => summary.refused += 1,
            (TransferResult::Failed, _, _) => summary.failed += 1,
            (TransferResult::Ok, TransferKind::Axfr, _) => summary.axfr += 1,
            (TransferResult::Ok, TransferKind::Ixfr, true) => summary.ixfr_delta += 1,
            (TransferResult::Ok, TransferKind::Ixfr, false) => summary.ixfr_full += 1,
        }
    }

    summary
}

/// Resolve the addresses the secondary resolves to now, which key the transfer log
/// rows; none when it does not resolve.
async fn resolve_ips(cx: &Context, secondary: &Secondary) -> Vec<IpAddr> {
    let timeout = cx.config().dns.notify.timeout();
    match dns_client::resolve_address_entry(&secondary.address, timeout).await {
        Ok(addrs) => addrs.iter().map(SocketAddr::ip).collect(),
        Err(_) => Vec::new(),
    }
}
