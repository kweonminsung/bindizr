//! Diagnose a named secondary, including disabled ones, or the enabled secondary group.

use std::net::SocketAddr;

use bindizr_core::dns::name::ZoneName;
use bindizr_core::dns::{Serial, address};
use bindizr_core::model::role_grant::Action;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::{
    CheckSecondariesResponse, CheckSecondaryResponse, SecondaryTransferSummaryResponse,
};
use crate::{Context, dns_client, notify, probe};

/// Check one secondary, enabled or not: resolve it, compare its catalog serial
/// with Bindizr's listener, and send catalog NOTIFY.
pub async fn check(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<CheckSecondaryResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryManage)?;

    let secondary = super::lookup_by_name(cx, name).await?;

    let config = cx.config();
    let catalog_zone = config.dns.catalog_zone_name.clone();
    let timeout = config.dns.notify.timeout();

    // The listener's serial is the reference: it reflects the catalog's
    // current membership, which a stored serial would not.
    let dns_addr = SocketAddr::new(
        address::loopback_if_unspecified(config.dns.listen_addr),
        config.dns.listen_port,
    );

    let (catalog_serial, listener_error) =
        match dns_client::probe::probe_server(dns_addr, &catalog_zone, timeout).await {
            Ok(serial) => (Some(serial), None),
            Err(error) => (None, Some(format!("{}: {}", dns_addr, error))),
        };

    let (addresses, resolve_error) =
        match dns_client::resolve_address_entry(&secondary.address, timeout).await {
            Ok(addrs) => (addrs.iter().map(ToString::to_string).collect(), None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
    let catalog = probe::probe_secondary(cx, &catalog_zone, &secondary, catalog_serial).await?;
    let notifies = notify::send_notify_to_secondary(cx, &catalog_zone, &secondary).await?;
    let transfers = super::summarize_transfers(cx, &secondary).await?;

    Ok(CheckSecondaryResponse {
        secondary: super::load_response(cx, secondary).await?,
        addresses,
        resolve_error,
        catalog_zone_name: catalog_zone.to_string(),
        catalog_serial,
        listener_error,
        catalog,
        notifies,
        transfers,
    })
}

/// Diagnose enabled secondaries against the listener's observed catalog serial.
/// Capture SOA status before NOTIFY can trigger a catalog transfer.
pub async fn check_enabled(
    cx: &Context,
    caller: &Caller,
    catalog_zone: &ZoneName,
    catalog_serial: Option<Serial>,
) -> Result<CheckSecondariesResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryManage)?;

    let secondaries = probe::probe_secondaries(cx, catalog_zone, catalog_serial).await?;
    let notifies = notify::send_notify_to_secondaries(cx, catalog_zone).await?;
    let mut transfers = Vec::new();

    for secondary in super::list_enabled(cx).await? {
        transfers.push(SecondaryTransferSummaryResponse {
            summary: super::summarize_transfers(cx, &secondary).await?,
            secondary_name: secondary.name,
            address: secondary.address.to_string(),
        });
    }

    Ok(CheckSecondariesResponse {
        secondaries,
        notifies,
        transfers,
    })
}
