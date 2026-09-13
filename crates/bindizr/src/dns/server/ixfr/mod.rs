//! Serving IXFR (RFC 1995): every gate that sends a client to AXFR instead,
//! then the delta itself.

mod delta;
mod send;

use std::{collections::HashMap, net::IpAddr};

use bindizr_core::{
    dns::{message, message::Rtype, tsig::TransferSigner},
    log_info, log_warn,
    model::zone_version::ZoneVersion,
};
use bindizr_service::zone::ZoneService;
use tokio::net::TcpStream;

use self::{
    delta::{delta_gap, is_delta_no_smaller_than_zone},
    send::{IxfrSendError, send_ixfr_response, send_soa_response},
};
use super::{axfr, catalog};
use crate::dns::error::XfrError;

pub(crate) async fn handle_ixfr(
    stream: &mut TcpStream,
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    signer: Option<TransferSigner>,
) -> Result<(), XfrError> {
    let zone_name_str = query.zone_name.as_str();

    log_info!(
        "IXFR request for zone {:?} from {}, client_serial={:?}",
        zone_name_str,
        client_ip,
        query.client_serial
    );

    if catalog::is_catalog_zone(zone_name_str) {
        log_info!("IXFR: Catalog zone requested, falling back to AXFR");
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, signer).await;
    }

    let zone = ZoneService::find_by_name(zone_name_str)
        .await?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    let current_serial = bindizr_core::dns::serial_to_u32(zone.serial)?;

    let client_serial = match query.client_serial {
        Some(s) => s,
        None => {
            log_warn!("IXFR: No client serial provided, falling back to AXFR");
            return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, signer).await;
        }
    };

    if client_serial == current_serial {
        log_info!("IXFR: Client is up-to-date (serial={})", current_serial);
        let current_soa =
            match ZoneService::find_version_by_serial(zone.id, current_serial as i32).await? {
                Some(version) => version,
                None => {
                    log_warn!("IXFR: Missing SOA version, falling back to AXFR");
                    return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, signer).await;
                }
            };
        return send_soa_response(stream, query, &current_soa, signer).await;
    }

    // Plain comparison, not the RFC 1982 serial arithmetic RFC 1995 assumes:
    // bindizr's serials stop at i32::MAX and never wrap, so mod-2^32 ordering
    // could only matter for a client holding a larger serial from a previous
    // primary, which needs a reload there rather than an IXFR.
    if client_serial > current_serial {
        log_warn!(
            "IXFR: Client serial {} > current serial {}, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, signer).await;
    }

    if is_delta_no_smaller_than_zone(&zone, client_serial, current_serial).await? {
        log_info!(
            "IXFR: Delta from serial {} to {} is no smaller than the zone, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, signer).await;
    }

    let changes = ZoneService::list_journal_between_serials(
        zone.id,
        client_serial as i32,
        current_serial as i32,
    )
    .await?;

    if changes.is_empty() {
        log_warn!(
            "IXFR: No history available for serial {} to {}, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, signer).await;
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
        log_warn!("IXFR: {}, falling back to AXFR", gap);
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, signer).await;
    }

    log_info!(
        "IXFR: Sending {} changes across {} serial steps from {} to {}",
        changes.len(),
        journal_serials.len(),
        client_serial,
        current_serial
    );

    match send_ixfr_response(
        stream,
        query,
        &zone,
        client_serial,
        &changes,
        &versions_by_serial,
        signer,
    )
    .await
    {
        Ok(()) => {}
        // Nothing was written yet, so a full AXFR is still a valid response.
        Err(IxfrSendError::NotStarted { error, signer }) => {
            log_warn!(
                "IXFR: Failed to build incremental response ({}), falling back to AXFR",
                error
            );
            return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR, signer.map(|s| *s))
                .await;
        }
        // Bytes already sent; a fallback AXFR would corrupt the partial IXFR.
        Err(IxfrSendError::Partial(err)) => {
            log_warn!(
                "IXFR: aborting after partial send, not falling back: {}",
                err
            );
            return Err(err);
        }
    }

    log_info!("IXFR completed for zone {}", zone_name_str);

    Ok(())
}
