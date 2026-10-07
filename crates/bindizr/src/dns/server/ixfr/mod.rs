//! Serving IXFR (RFC 1995): every gate that sends a client to AXFR instead,
//! then the delta itself.

mod send;

use std::{collections::HashMap, net::IpAddr};

use bindizr_core::{
    dns::{Serial, message, message::Rtype},
    model::{transfer::TransferKind, zone_version::ZoneVersion},
};
use bindizr_service::{
    transfer,
    zone::{self, TransferAccess, TransferDelta},
};

use self::send::{IxfrSendError, send_ixfr_response, send_soa_response};
use super::{auth::TransferIdentity, axfr};
use crate::dns::{error::XfrError, server::DnsContext, stream::DnsStream};

/// Answer an IXFR request using journal changes or an AXFR fallback.
pub(crate) async fn handle_ixfr(
    dns_cx: &DnsContext,
    stream: &mut DnsStream,
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    identity: &mut TransferIdentity,
) -> Result<(), XfrError> {
    let cx = dns_cx.daemon();
    let zone_name_str = query.zone_name.as_str();

    log::info!(
        "IXFR request for zone {:?} from {}, client_serial={:?}",
        zone_name_str,
        client_ip,
        query.client_serial
    );

    // Choose a full transfer or an SOA-only reply before loading incremental history.
    if cx.config().dns.is_catalog_zone(zone_name_str) {
        log::info!("IXFR: Catalog zone requested, falling back to AXFR");
        return axfr::handle_axfr(dns_cx, stream, query, client_ip, Rtype::IXFR, identity).await;
    }

    let client_serial = match query.client_serial {
        Some(s) => Serial::from(s),
        None => {
            log::warn!("IXFR: No client serial provided, falling back to AXFR");
            return axfr::handle_axfr(dns_cx, stream, query, client_ip, Rtype::IXFR, identity)
                .await;
        }
    };

    // Zone, grant and delta are read in one transaction. A name the zone type
    // refuses is answered NOTAUTH like a missing zone.
    let access = match zone::normalize_name(zone_name_str) {
        Ok(zone_name) => {
            zone::authorize_transfer_delta_by_name(
                cx,
                &zone_name,
                identity.key.as_ref(),
                client_serial,
            )
            .await?
        }
        Err(_) => TransferAccess::NotAuth,
    };
    let (zone, delta) = match access {
        TransferAccess::Granted(found) => found,
        TransferAccess::NotAuth => {
            return Err(XfrError::NotAuth(zone_name_str.to_string()));
        }
        TransferAccess::Refused(reason) => return Err(XfrError::Refused(reason)),
    };
    let current_serial = zone.serial;

    let (changes, versions) = match delta {
        TransferDelta::UpToDate(current_soa) => {
            log::info!("IXFR: Client is up-to-date (serial={})", current_serial);
            return send_soa_response(stream, query, &current_soa, identity.signer.take()).await;
        }
        TransferDelta::Full => {
            log::info!(
                "IXFR: No incremental answer from serial {} to {}, falling back to AXFR",
                client_serial,
                current_serial
            );
            return axfr::handle_axfr(dns_cx, stream, query, client_ip, Rtype::IXFR, identity)
                .await;
        }
        TransferDelta::Changes { changes, versions } => (changes, versions),
    };

    let versions_by_serial: HashMap<Serial, ZoneVersion> = versions
        .into_iter()
        .map(|version| (version.serial, version))
        .collect();

    log::info!(
        "IXFR: Sending {} changes across {} serial steps from {} to {}",
        changes.len(),
        // The versions span the client's serial and every step after it.
        versions_by_serial.len().saturating_sub(1),
        client_serial,
        current_serial
    );

    // The service checked the delta has no gap; a failure still falls back
    // to AXFR only while no bytes have reached the client.
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
            return axfr::handle_axfr(dns_cx, stream, query, client_ip, Rtype::IXFR, identity)
                .await;
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
    transfer::save_ok(
        cx,
        client_ip,
        zone.id,
        TransferKind::Ixfr,
        stream.transport(),
        true,
        current_serial,
    )
    .await;

    Ok(())
}
