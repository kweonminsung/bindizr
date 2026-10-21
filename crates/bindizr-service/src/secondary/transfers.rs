//! Read the transfer history matching a secondary's current addresses.

use std::net::{IpAddr, SocketAddr};

use bindizr_core::model::role_grant::Action;

use super::lookup_by_name;
use crate::{
    Context,
    authorization::Caller,
    dns_client::resolve_address_entry,
    error::ServiceError,
    model::secondary::Secondary,
    pagination::validate_page_limit,
    transfer,
    types::{
        SecondaryTransferFilter, SecondaryTransfersResponse, TransferResponse,
        TransferSummaryResponse,
    },
    zone,
};

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
    validate_page_limit(Some(limit))?;

    let secondary = lookup_by_name(cx, name).await?;

    let zone_filter = filter
        .zone_name
        .as_deref()
        .map(zone::normalize_name)
        .transpose()?;

    let served = transfer::list_by_clients(cx, &resolve_ips(cx, &secondary).await).await?;
    let summary = TransferSummaryResponse::from(served.as_slice());
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
    Ok(TransferSummaryResponse::from(served.as_slice()))
}

/// The addresses the secondary resolves to now, which key the transfer
/// rows; none when it does not resolve.
async fn resolve_ips(cx: &Context, secondary: &Secondary) -> Vec<IpAddr> {
    let timeout = cx.config().dns.notify.timeout();
    match resolve_address_entry(&secondary.address, timeout).await {
        Ok(addrs) => addrs.iter().map(SocketAddr::ip).collect(),
        Err(_) => Vec::new(),
    }
}
