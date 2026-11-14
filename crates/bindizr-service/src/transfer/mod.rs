//! The transfer log: each transfer, refusal, or failure a client was answered,
//! kept across restarts and instances.

use std::cmp::Reverse;
use std::net::IpAddr;

use bindizr_core::config::SavedTransfers;
use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::transfer::{
    TransferKind, TransferLog, TransferLogWithZone, TransferResult, TransferTransport,
};
use bindizr_core::model::zone::ZoneId;
use bindizr_db::transfer_log::TransferLogFilter;
use chrono::Utc;

use crate::Context;
use crate::error::ServiceError;

/// Save a transfer answered for `zone_id` up to `serial`. A failure to
/// save is logged; the transfer already went out.
pub async fn save_ok(
    cx: &Context,
    client: IpAddr,
    zone_id: ZoneId,
    kind: TransferKind,
    transport: TransferTransport,
    incremental: bool,
    serial: Serial,
) {
    // `history.transfer.save = "unserved"` keeps refusals and failures alone.
    if cx.config().history.transfer.save == SavedTransfers::Unserved {
        return;
    }

    let saved = bindizr_db::transfer_log::create(
        cx.db(),
        TransferLog {
            client_addr: client.to_string(),
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
        log::warn!("Failed to save a transfer: {}", error);
    }
}

/// Save a refusal for the zone `zone_name` names.
pub async fn save_refused(
    cx: &Context,
    client: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    transport: TransferTransport,
    reason: String,
) {
    save_unserved(
        cx,
        client,
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
    client: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    transport: TransferTransport,
    error: String,
) {
    save_unserved(
        cx,
        client,
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
    client: IpAddr,
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
            log::warn!("Failed to save a transfer of {}: {}", zone_name, error);
            return;
        }
    };
    let saved = bindizr_db::transfer_log::create(
        cx.db(),
        TransferLog {
            client_addr: client.to_string(),
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
        log::warn!("Failed to save a transfer of {}: {}", zone_name, error);
    }
}

/// The transfers `filter` selects among those answered to any of `clients`,
/// newest first.
pub(crate) async fn list_by_clients(
    cx: &Context,
    clients: &[IpAddr],
    filter: &TransferLogFilter,
) -> Result<Vec<TransferLogWithZone>, ServiceError> {
    let mut logs = Vec::new();

    for client in clients {
        logs.extend(
            bindizr_db::transfer_log::list_by_client_addr_and_filter_with_zone(
                cx.db(),
                &client.to_string(),
                filter,
            )
            .await?,
        );
    }

    // Each address gave its newest `limit`, so the newest of them all are here.
    logs.sort_by_key(|log| Reverse(log.served_at));

    if let Some(limit) = filter.limit {
        logs.truncate(limit as usize);
    }

    Ok(logs)
}

/// The latest transfer of each zone answered to each of `clients`.
pub(crate) async fn list_latest_by_clients(
    cx: &Context,
    clients: &[IpAddr],
) -> Result<Vec<TransferLogWithZone>, ServiceError> {
    let mut logs = Vec::new();

    for client in clients {
        logs.extend(
            bindizr_db::transfer_log::list_by_client_addr_with_zone_latest_per_zone(
                cx.db(),
                &client.to_string(),
            )
            .await?,
        );
    }

    Ok(logs)
}

/// The latest transfer of `zone_name` answered to any of `clients`.
pub(crate) async fn find_by_clients_and_zone_name(
    cx: &Context,
    clients: &[IpAddr],
    zone_name: &ZoneName,
) -> Result<Option<TransferLogWithZone>, ServiceError> {
    let filter = TransferLogFilter {
        zone_name: Some(zone_name.clone()),
        limit: Some(1),
        ..TransferLogFilter::default()
    };

    Ok(list_by_clients(cx, clients, &filter)
        .await?
        .into_iter()
        .next())
}

#[cfg(test)]
mod tests;
