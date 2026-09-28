//! What Bindizr served each client: the latest transfer per client address
//! and zone, refusals and failures included, kept in the database so a
//! secondary's transfers read back across restarts and instances.

use std::net::IpAddr;

use bindizr_core::{
    dns::serial_to_i32,
    model::transfer::{Transfer, TransferKind, TransferResult, TransferWithZone},
};
use chrono::Utc;

use crate::{Context, db, error::ServiceError};

/// Save a transfer answered for `zone_id` up to `serial`. A failure to
/// save is logged; the transfer already went out.
pub async fn save_ok(
    cx: &Context,
    client: IpAddr,
    zone_id: i32,
    kind: TransferKind,
    incremental: bool,
    serial: u32,
) {
    let saved = db::transfer::upsert(
        cx.db(),
        Transfer {
            client_addr: client.to_string(),
            zone_id,
            kind,
            result: TransferResult::Ok,
            incremental,
            serial: serial_to_i32(serial).ok(),
            served_at: Utc::now(),
            error: None,
        },
    )
    .await;
    if let Err(e) = saved {
        log::warn!("Failed to save a transfer: {}", e);
    }
}

/// Save a refusal for the zone `zone_name` names.
pub async fn save_refused(
    cx: &Context,
    client: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    reason: String,
) {
    save_unserved(cx, client, zone_name, kind, TransferResult::Refused, reason).await;
}

/// Save a transfer of the zone `zone_name` names that was allowed and
/// then broke off.
pub async fn save_failed(
    cx: &Context,
    client: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    error: String,
) {
    save_unserved(cx, client, zone_name, kind, TransferResult::Failed, error).await;
}

/// Save a refusal or failure for the zone `zone_name` names; a zone
/// Bindizr does not have leaves no row, and a failure to save is logged.
async fn save_unserved(
    cx: &Context,
    client: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    result: TransferResult,
    error: String,
) {
    let zone = match db::zone::get_by_name(cx.db(), zone_name).await {
        Ok(Some(zone)) => zone,
        Ok(None) => return,
        Err(e) => {
            log::warn!("Failed to save a transfer of {}: {}", zone_name, e);
            return;
        }
    };
    let saved = db::transfer::upsert(
        cx.db(),
        Transfer {
            client_addr: client.to_string(),
            zone_id: zone.id,
            kind,
            result,
            incremental: false,
            serial: None,
            served_at: Utc::now(),
            error: Some(error),
        },
    )
    .await;
    if let Err(e) = saved {
        log::warn!("Failed to save a transfer of {}: {}", zone_name, e);
    }
}

/// The transfers served to any of `clients`, newest first.
pub(crate) async fn list_by_clients(
    cx: &Context,
    clients: &[IpAddr],
) -> Result<Vec<TransferWithZone>, ServiceError> {
    let mut transfers = Vec::new();
    for client in clients {
        transfers.extend(
            db::transfer::list_by_client_addr_with_zone(cx.db(), &client.to_string()).await?,
        );
    }
    transfers.sort_by_key(|transfer| std::cmp::Reverse(transfer.served_at));
    Ok(transfers)
}

/// The latest transfer of `zone_name` served to any of `clients`.
pub(crate) async fn find_by_clients_and_zone_name(
    cx: &Context,
    clients: &[IpAddr],
    zone_name: &str,
) -> Result<Option<TransferWithZone>, ServiceError> {
    let mut latest: Option<TransferWithZone> = None;
    for client in clients {
        if let Some(transfer) = db::transfer::get_by_client_addr_and_zone_name_with_zone(
            cx.db(),
            &client.to_string(),
            zone_name,
        )
        .await?
            && latest
                .as_ref()
                .is_none_or(|found| transfer.served_at > found.served_at)
        {
            latest = Some(transfer);
        }
    }
    Ok(latest)
}
