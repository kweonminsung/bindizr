//! The transfer log: each transfer, refusal, or failure a client was answered,
//! kept across restarts and instances; reads require `log:read`.

use std::net::IpAddr;

use bindizr_core::config::SavedTransfers;
use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::transfer::{
    TransferKind, TransferLog, TransferLogWithZone, TransferResult, TransferTransport,
};
use bindizr_core::model::zone::ZoneId;
use chrono::Utc;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::{PaginatedResponse, TransferLogFilter, TransferLogResponse};
use crate::{Context, pagination, secondary, zone};

/// Save a transfer answered for `zone_id` up to `serial`. A failure to
/// save is logged; the transfer already went out.
pub async fn save_ok(
    cx: &Context,
    client_ip: IpAddr,
    zone_id: ZoneId,
    kind: TransferKind,
    transport: TransferTransport,
    incremental: bool,
    serial: Serial,
) {
    // `transfer_log.save = "unserved"` keeps refusals and failures alone.
    if cx.config().transfer_log.save == SavedTransfers::Unserved {
        return;
    }

    let saved = bindizr_db::transfer_log::create(
        cx.db(),
        TransferLog {
            client_addr: client_ip.to_string(),
            zone_id,
            kind,
            result: TransferResult::Ok,
            transport,
            incremental,
            serial: Some(serial),
            served_at: Utc::now(),
            error: None,
        },
    )
    .await;

    if let Err(error) = saved {
        log::warn!("Failed to save a transfer: {error}");
    }
}

/// Save a refusal for the zone `zone_name` names.
pub async fn save_refused(
    cx: &Context,
    client_ip: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    transport: TransferTransport,
    reason: String,
) {
    save_unserved(
        cx,
        client_ip,
        zone_name,
        kind,
        transport,
        TransferResult::Refused,
        reason,
    )
    .await;
}

/// Save a transfer of the zone `zone_name` names that was allowed and
/// then broke off.
pub async fn save_failed(
    cx: &Context,
    client_ip: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    transport: TransferTransport,
    error: String,
) {
    save_unserved(
        cx,
        client_ip,
        zone_name,
        kind,
        transport,
        TransferResult::Failed,
        error,
    )
    .await;
}

/// Save a refusal or failure for the zone `zone_name` names; a zone
/// Bindizr does not have leaves no row, and a failure to save is logged.
async fn save_unserved(
    cx: &Context,
    client_ip: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    transport: TransferTransport,
    result: TransferResult,
    error: String,
) {
    let Ok(zone_name) = ZoneName::parse(zone_name) else {
        return;
    };

    let zone = match bindizr_db::zone::get_by_name(cx.db(), &zone_name).await {
        Ok(Some(zone)) => zone,
        Ok(None) => return,
        Err(error) => {
            log::warn!("Failed to save a transfer of {zone_name}: {error}");
            return;
        }
    };
    let saved = bindizr_db::transfer_log::create(
        cx.db(),
        TransferLog {
            client_addr: client_ip.to_string(),
            zone_id: zone.id,
            kind,
            result,
            transport,
            incremental: false,
            serial: None,
            served_at: Utc::now(),
            error: Some(error),
        },
    )
    .await;

    if let Err(error) = saved {
        log::warn!("Failed to save a transfer of {zone_name}: {error}");
    }
}

/// List the transfer log rows `filter` selects, newest first. Count and page
/// are plain statements; drift between the two is accepted.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    filter: &TransferLogFilter,
) -> Result<PaginatedResponse<TransferLogResponse>, ServiceError> {
    caller.authorize_action(Action::LogRead)?;

    let filter = normalize_filter(cx, filter).await?;

    let total = bindizr_db::transfer_log::count_by_filter(cx.db(), &filter).await?;
    let logs = bindizr_db::transfer_log::list_by_filter_with_zone(cx.db(), &filter).await?;

    Ok(pagination::build_paginated_response(
        logs.iter().map(TransferLogResponse::from).collect(),
        filter.limit,
        filter.offset,
        total,
    ))
}

/// Parse the listing's zone, result and address, resolve its secondary to the
/// addresses that key its rows, and bound its page. A secondary and an address
/// together select the address only when the secondary resolves to it.
async fn normalize_filter(
    cx: &Context,
    filter: &TransferLogFilter,
) -> Result<bindizr_db::transfer_log::TransferLogFilter, ServiceError> {
    let zone_name = filter
        .zone_name
        .as_deref()
        .map(zone::normalize_name)
        .transpose()?;
    let result = filter
        .result
        .as_deref()
        .map(str::trim)
        .filter(|result| !result.is_empty())
        .map(str::parse::<TransferResult>)
        .transpose()
        .map_err(ServiceError::invalid_input)?;
    let address = filter
        .address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .map(|address| {
            address.parse::<IpAddr>().map_err(|_| {
                ServiceError::invalid_input(format!("address '{address}' is not an IP address"))
            })
        })
        .transpose()?;

    if let (Some(since), Some(until)) = (filter.since, filter.until)
        && since >= until
    {
        return Err(ServiceError::invalid_input("since must be before until"));
    }

    pagination::validate_page_limit(filter.limit)?;

    let secondary_ips = match filter.secondary_name.as_deref() {
        Some(secondary_name) => {
            let secondary = secondary::lookup_by_name(cx, secondary_name).await?;
            Some(secondary::resolve_ips(cx, &secondary).await)
        }
        None => None,
    };
    let client_ips: Option<Vec<IpAddr>> = match (secondary_ips, address) {
        (Some(secondary_ips), Some(address)) => Some(
            secondary_ips
                .into_iter()
                .filter(|ip| *ip == address)
                .collect(),
        ),
        (Some(secondary_ips), None) => Some(secondary_ips),
        (None, Some(address)) => Some(vec![address]),
        (None, None) => None,
    };

    Ok(bindizr_db::transfer_log::TransferLogFilter {
        client_addrs: client_ips.map(|ips| ips.iter().map(IpAddr::to_string).collect()),
        zone_name,
        result,
        since: filter.since,
        until: filter.until,
        limit: filter.limit,
        offset: filter.offset,
    })
}

/// List the latest transfer of each zone answered to each of `client_ips`.
pub(crate) async fn list_latest_by_clients(
    cx: &Context,
    client_ips: &[IpAddr],
) -> Result<Vec<TransferLogWithZone>, ServiceError> {
    let mut logs = Vec::new();

    for client_ip in client_ips {
        logs.extend(
            bindizr_db::transfer_log::list_by_client_addr_with_zone_latest_per_zone(
                cx.db(),
                &client_ip.to_string(),
            )
            .await?,
        );
    }

    Ok(logs)
}

/// Find the latest transfer of `zone_name` answered to any of `client_ips`.
pub(crate) async fn find_by_clients_and_zone_name(
    cx: &Context,
    client_ips: &[IpAddr],
    zone_name: &ZoneName,
) -> Result<Option<TransferLogWithZone>, ServiceError> {
    let filter = bindizr_db::transfer_log::TransferLogFilter {
        client_addrs: Some(client_ips.iter().map(IpAddr::to_string).collect()),
        zone_name: Some(zone_name.clone()),
        limit: Some(1),
        ..Default::default()
    };

    Ok(
        bindizr_db::transfer_log::list_by_filter_with_zone(cx.db(), &filter)
            .await?
            .into_iter()
            .next(),
    )
}

#[cfg(test)]
mod tests;
