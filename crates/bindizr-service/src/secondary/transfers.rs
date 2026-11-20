//! Summarize the transfer log rows matching a secondary's current addresses.

use std::net::IpAddr;

use bindizr_core::model::secondary::Secondary;
use bindizr_core::model::transfer::{TransferKind, TransferLogWithZone, TransferResult};

use crate::error::ServiceError;
use crate::types::TransferSummaryResponse;
use crate::{Context, dns_client, transfer};

/// Summarize how Bindizr last served `secondary` each zone, for the check and doctor.
pub(crate) async fn summarize_transfers(
    cx: &Context,
    secondary: &Secondary,
) -> Result<TransferSummaryResponse, ServiceError> {
    let latest = transfer::list_latest_by_clients(cx, &resolve_ips(cx, secondary).await).await?;
    Ok(build_transfer_summary(&latest))
}

/// Count each zone by its latest transfer, one row per zone in `latest`.
fn build_transfer_summary(latest: &[TransferLogWithZone]) -> TransferSummaryResponse {
    let mut summary = TransferSummaryResponse {
        zones: latest.len() as u64,
        axfr: 0,
        ixfr_full: 0,
        ixfr_delta: 0,
        refused: 0,
        failed: 0,
    };

    for TransferLogWithZone { log, .. } in latest {
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
pub(crate) async fn resolve_ips(cx: &Context, secondary: &Secondary) -> Vec<IpAddr> {
    let timeout = cx.config().dns.notify.timeout();
    match dns_client::resolve_address_entry(&secondary.address, timeout).await {
        // Transfer rows store an IPv4-mapped client as IPv4.
        Ok(addrs) => addrs.iter().map(|addr| addr.ip().to_canonical()).collect(),
        Err(_) => Vec::new(),
    }
}
