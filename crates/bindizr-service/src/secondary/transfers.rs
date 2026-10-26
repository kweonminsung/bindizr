//! Read the transfer history matching a secondary's current addresses.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use bindizr_core::model::role_grant::Action;
use bindizr_core::model::transfer::{TransferKind, TransferResult, TransferWithZone};

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::model::secondary::Secondary;
use crate::types::{
    SecondaryTransferFilter, SecondaryTransfersResponse, TransferResponse, TransferSummaryResponse,
};
use crate::{Context, dns_client, pagination, transfer, zone};

/// The transfers Bindizr served `name`, newest first, with how each zone
/// was last served.
pub async fn list_transfers(
    cx: &Context,
    caller: &Caller,
    name: &str,
    filter: SecondaryTransferFilter,
) -> Result<SecondaryTransfersResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryRead)?;
    let limit = filter.limit.unwrap_or(1000);
    pagination::validate_page_limit(Some(limit))?;

    let secondary = super::lookup_by_name(cx, name).await?;

    let zone_filter = filter
        .zone_name
        .as_deref()
        .map(zone::normalize_name)
        .transpose()?;

    let served = transfer::list_by_clients(cx, &resolve_ips(cx, &secondary).await).await?;
    let summary = build_transfer_summary(&served);
    let transfers = served
        .iter()
        .filter(|transfer| {
            zone_filter
                .as_ref()
                .is_none_or(|zone| transfer.zone_name == *zone)
        })
        .take(limit as usize)
        .map(TransferResponse::from)
        .collect();

    Ok(SecondaryTransfersResponse {
        secondary_name: secondary.name,
        address: secondary.address.to_string(),
        summary,
        transfers,
    })
}

/// How Bindizr served `secondary`, for the check and doctor.
pub(crate) async fn summarize_transfers(
    cx: &Context,
    secondary: &Secondary,
) -> Result<TransferSummaryResponse, ServiceError> {
    let served = transfer::list_by_clients(cx, &resolve_ips(cx, secondary).await).await?;
    Ok(build_transfer_summary(&served))
}

/// Count each zone by its latest transfer among `transfers`.
fn build_transfer_summary(transfers: &[TransferWithZone]) -> TransferSummaryResponse {
    let mut latest: HashMap<&str, &TransferWithZone> = HashMap::new();

    for transfer in transfers {
        let entry = latest
            .entry(transfer.zone_name.as_str())
            .or_insert(transfer);
        if transfer.served_at > entry.served_at {
            *entry = transfer;
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

    for transfer in latest.values() {
        match (transfer.result, transfer.kind, transfer.incremental) {
            (TransferResult::Refused, _, _) => summary.refused += 1,
            (TransferResult::Failed, _, _) => summary.failed += 1,
            (TransferResult::Ok, TransferKind::Axfr, _) => summary.axfr += 1,
            (TransferResult::Ok, TransferKind::Ixfr, true) => summary.ixfr_delta += 1,
            (TransferResult::Ok, TransferKind::Ixfr, false) => summary.ixfr_full += 1,
        }
    }

    summary
}

/// The addresses the secondary resolves to now, which key the transfer
/// rows; none when it does not resolve.
async fn resolve_ips(cx: &Context, secondary: &Secondary) -> Vec<IpAddr> {
    let timeout = cx.config().dns.notify.timeout();
    match dns_client::resolve_address_entry(&secondary.address, timeout).await {
        Ok(addrs) => addrs.iter().map(SocketAddr::ip).collect(),
        Err(_) => Vec::new(),
    }
}
