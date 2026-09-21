//! Serving IXFR (RFC 1995): every gate that sends a client to AXFR instead,
//! then the delta itself.

mod delta;
mod send;

use std::{collections::HashMap, net::IpAddr};

use bindizr_core::{
    config::bindizr_config,
    dns::{message, message::Rtype},
    model::zone_version::ZoneVersion,
};
use bindizr_service::zone::{TransferAccess, ZoneService};
use tokio::net::TcpStream;

use self::{
    delta::delta_gap,
    send::{IxfrSendError, send_ixfr_response, send_soa_response},
};
use super::{auth::TransferIdentity, axfr};
use crate::dns::error::XfrError;

/// Answer an IXFR request using journal changes or an AXFR fallback.
pub(crate) async fn handle_ixfr(
    stream: &mut TcpStream,
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    identity: &mut TransferIdentity,
) -> Result<(), XfrError> {
    let zone_name_str = query.zone_name.as_str();

    log::info!(
        "IXFR request for zone {:?} from {}, client_serial={:?}",
        zone_name_str,
        client_ip,
        query.client_serial
    );

    // Choose a full transfer or an SOA-only reply before loading incremental history.
    if bindizr_config().dns.is_catalog_zone(zone_name_str) {
        log::info!("IXFR: Catalog zone requested, falling back to AXFR");
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, identity).await;
    }

    // The zone and the grant are decided on one locked row; the journal
    // reads that follow use its id, so the delta is that zone's.
    let zone = match ZoneService::authorize_transfer_by_name(zone_name_str, identity.key.as_ref())
        .await?
    {
        TransferAccess::Granted(zone) => zone,
        TransferAccess::NotZone => {
            return Err(XfrError::ZoneNotFound(zone_name_str.to_string()));
        }
        TransferAccess::Refused(reason) => return Err(XfrError::Refused(reason)),
    };

    let current_serial = bindizr_core::dns::serial_to_u32(zone.serial)?;

    let client_serial = match query.client_serial {
        Some(s) => s,
        None => {
            log::warn!("IXFR: No client serial provided, falling back to AXFR");
            return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, identity).await;
        }
    };

    if client_serial == current_serial {
        log::info!("IXFR: Client is up-to-date (serial={})", current_serial);
        let current_soa = match ZoneService::find_version_by_serial(zone.id, current_serial as i32)
            .await?
        {
            Some(version) => version,
            None => {
                log::warn!("IXFR: Missing SOA version, falling back to AXFR");
                return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, identity).await;
            }
        };
        return send_soa_response(stream, query, &current_soa, identity.signer.take()).await;
    }

    // Plain comparison, not the RFC 1982 serial arithmetic RFC 1995 assumes:
    // bindizr's serials stop at i32::MAX and never wrap, so mod-2^32 ordering
    // could only matter for a client holding a larger serial from a previous
    // primary, which needs a reload there rather than an IXFR.
    if client_serial > current_serial {
        log::warn!(
            "IXFR: Client serial {} > current serial {}, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, identity).await;
    }

    // RFC 1995, Section 2 lets a server answer with a full transfer once the
    // incremental one stops being smaller; counting first also keeps a
    // long-absent secondary from pulling its whole absence into memory. Rows,
    // not bytes: summing lengths would read the rows this decides whether to read.
    let delta_rows = ZoneService::count_changes_between_serials(
        zone.id,
        client_serial as i32,
        current_serial as i32,
    )
    .await?;
    if delta_rows >= ZoneService::count_transfer_records(zone.name.as_str()).await? {
        log::info!(
            "IXFR: Delta from serial {} to {} is no smaller than the zone, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, identity).await;
    }

    // Pair journal steps with their SOA versions to prove the delta has no gaps.
    let changes = ZoneService::list_changes_between_serials(
        zone.id,
        client_serial as i32,
        current_serial as i32,
    )
    .await?;

    if changes.is_empty() {
        log::warn!(
            "IXFR: No history available for serial {} to {}, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, identity).await;
    }

    let mut journal_serials: Vec<u32> = changes
        .iter()
        .map(|c| bindizr_core::dns::serial_to_u32(c.serial))
        .collect::<Result<_, _>>()?;
    journal_serials.sort_unstable();
    journal_serials.dedup();

    let mut versions_by_serial: HashMap<u32, ZoneVersion> = HashMap::new();
    versions_by_serial.reserve(journal_serials.len() + 1);

    for version in ZoneService::list_versions_in_serial_range(
        zone.id,
        client_serial as i32,
        current_serial as i32,
    )
    .await?
    {
        if let Ok(serial) = bindizr_core::dns::serial_to_u32(version.serial) {
            versions_by_serial.insert(serial, version);
        }
    }

    let version_serials: Vec<u32> = versions_by_serial.keys().copied().collect();
    if let Some(gap) = delta_gap(
        client_serial,
        current_serial,
        &journal_serials,
        &version_serials,
    ) {
        log::warn!("IXFR: {}, falling back to AXFR", gap);
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, identity).await;
    }

    log::info!(
        "IXFR: Sending {} changes across {} serial steps from {} to {}",
        changes.len(),
        journal_serials.len(),
        client_serial,
        current_serial
    );

    // Send only after validating the complete delta; fallback depends on whether
    // any bytes have reached the client.
    match send_ixfr_response(
        stream,
        query,
        &zone,
        client_serial,
        &changes,
        &versions_by_serial,
        identity.signer.take(),
    )
    .await
    {
        Ok(()) => {}
        // Nothing was written yet, so a full AXFR is still a valid response.
        Err(IxfrSendError::NotStarted {
            error,
            signer: signer_back,
        }) => {
            log::warn!(
                "IXFR: Failed to build incremental response ({}), falling back to AXFR",
                error
            );
            identity.signer = signer_back.map(|s| *s);
            return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, identity).await;
        }
        // Bytes already sent; a fallback AXFR would corrupt the partial IXFR.
        Err(IxfrSendError::Partial(err)) => {
            log::warn!(
                "IXFR: aborting after partial send, not falling back: {}",
                err
            );
            return Err(err);
        }
    }

    log::info!("IXFR completed for zone {}", zone_name_str);

    Ok(())
}
