//! Diagnose one registered secondary, including disabled ones.

use std::net::SocketAddr;

use bindizr_core::{dns::address::loopback_if_unspecified, model::role_grant::Action};

use super::{load_response, lookup_by_name, summarize_transfers};
use crate::{
    Context,
    authorization::Caller,
    dns_client::{probe as soa_client, resolve_address_entry},
    error::ServiceError,
    notify, probe,
    types::CheckSecondaryResponse,
};

/// Check one secondary, enabled or not: resolve it, compare its catalog serial
/// with Bindizr's listener, and send catalog NOTIFY.
pub async fn check(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<CheckSecondaryResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryManage)?;

    let secondary = lookup_by_name(cx, name).await?;

    let config = cx.config();
    let catalog_zone = config.dns.catalog_zone_name.clone();
    let timeout = config.dns.notify.timeout();

    // The listener's serial is the reference: it reflects the catalog's
    // current membership, which a stored serial would not.
    let dns_addr = SocketAddr::new(
        loopback_if_unspecified(config.dns.listen_addr),
        config.dns.listen_port,
    );

    let (catalog_serial, listener_error) =
        match soa_client::probe_server(dns_addr, &catalog_zone, timeout).await {
            Ok(serial) => (Some(serial), None),
            Err(error) => (None, Some(format!("{}: {}", dns_addr, error))),
        };

    let (addresses, resolve_error) = match resolve_address_entry(&secondary.address, timeout).await
    {
        Ok(addrs) => (addrs.iter().map(ToString::to_string).collect(), None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let catalog = probe::probe_secondary(cx, &catalog_zone, &secondary, catalog_serial).await?;
    let notifies = notify::send_notify_to_secondary(cx, &catalog_zone, &secondary).await?;
    let transfers = summarize_transfers(cx, &secondary).await?;

    Ok(CheckSecondaryResponse {
        secondary: load_response(cx, secondary).await?,
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
