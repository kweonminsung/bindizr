//! The transfer log: each transfer, refusal, or failure a client was answered,
//! kept across restarts and instances; reads require `log:read`.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
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
/// save is logged; the transfer already went out. An IXFR answered with the
/// SOA alone, its client already current, moved nothing and is not saved.
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
    if cx.config().transfer_log.save != SavedTransfers::All {
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
    if cx.config().transfer_log.save == SavedTransfers::None {
        return;
    }

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

    let secondary_name = filter.secondary_name.as_deref();
    let mut filter = normalize_filter(filter)?;

    // A secondary selects the addresses it resolves to, which key its rows;
    // with an address too, that address only when the secondary resolves to it.
    if let Some(secondary_name) = secondary_name {
        let secondary = secondary::lookup_by_name(cx, secondary_name).await?;
        let secondary_addrs = secondary::resolve_ips(cx, &secondary)
            .await
            .into_iter()
            .map(|ip| ip.to_string());

        filter.client_addrs = Some(match filter.client_addrs {
            Some(client_addrs) => secondary_addrs
                .filter(|addr| client_addrs.contains(addr))
                .collect(),
            None => secondary_addrs.collect(),
        });
    }

    let total = bindizr_db::transfer_log::count_by_filter(cx.db(), &filter).await?;
    let logs = bindizr_db::transfer_log::list_by_filter_with_zone(cx.db(), &filter).await?;

    Ok(pagination::build_paginated_response(
        logs.iter().map(TransferLogResponse::from).collect(),
        filter.limit,
        filter.offset,
        total,
    ))
}

/// Parse the listing's zone, result, address and order, and bound its page.
fn normalize_filter(
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

    // Newest first is the log's natural order, whatever the field.
    let defaults = bindizr_db::transfer_log::TransferLogFilter::default();
    let sort = pagination::parse_setting(filter.sort.as_deref(), defaults.sort)?;
    let order = pagination::parse_setting(filter.order.as_deref(), defaults.order)?;
    pagination::validate_page_limit(filter.limit)?;

    Ok(bindizr_db::transfer_log::TransferLogFilter {
        client_addrs: address.map(|address| vec![address.to_string()]),
        zone_name,
        result,
        since: filter.since,
        until: filter.until,
        sort,
        order,
        limit: filter.limit,
        offset: filter.offset,
    })
}

/// List the latest transfer of each zone answered to any of `client_ips`,
/// one row per zone, as `find_by_clients_and_zone_name` finds one zone's.
pub(crate) async fn list_latest_by_clients(
    cx: &Context,
    client_ips: &[IpAddr],
) -> Result<Vec<TransferLogWithZone>, ServiceError> {
    let mut latest: HashMap<ZoneName, TransferLogWithZone> = HashMap::new();

    for client_ip in client_ips {
        let logs = bindizr_db::transfer_log::list_by_client_addr_with_zone_latest_per_zone(
            cx.db(),
            &client_ip.to_string(),
        )
        .await?;

        // Each address has its own latest row; the newest across them wins.
        for log in logs {
            match latest.entry(log.zone_name.clone()) {
                Entry::Occupied(mut entry) if log.served_at > entry.get().served_at => {
                    entry.insert(log);
                }
                Entry::Occupied(_) => {}
                Entry::Vacant(entry) => {
                    entry.insert(log);
                }
            }
        }
    }

    Ok(latest.into_values().collect())
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
