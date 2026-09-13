//! Inbound DNS serving: AXFR/IXFR dispatch with TSIG or ACL gating, SOA
//! responses, catalog-zone generation, and RFC 2136 nsupdate handling.

use bindizr_core::dns::message;

pub(crate) mod acl;
pub(crate) mod auth;
pub(crate) mod axfr;
pub(crate) mod catalog;
pub(crate) mod ixfr;
pub(crate) mod nsupdate;
pub(crate) mod soa;
pub(crate) mod zone_cache;

use std::net::SocketAddr;

use auth::authorize_transfer;
use bindizr_core::{
    dns::message::{Rcode, Rtype},
    log_info, log_warn,
    metrics::{XfrResult, track_xfr},
};
use catalog::generate_catalog_zone;
use tokio::net::TcpStream;

use crate::dns::{error::XfrError, wire};

/// Initializes XFR support by ensuring the catalog zone exists.
pub(crate) async fn initialize() {
    match generate_catalog_zone().await {
        Ok((catalog, _)) => {
            log_info!(
                "Catalog zone '{}' is ready (serial: {})",
                catalog::CATALOG_ZONE_NAME,
                catalog.serial
            );
        }
        Err(e) => {
            log_warn!("Failed to generate catalog zone: {}", e);
        }
    }
}

pub(crate) fn is_xfr_query_type(qtype: Rtype) -> bool {
    matches!(qtype, Rtype::AXFR | Rtype::IXFR)
}

/// Called at the dispatch, so an IXFR falling back to AXFR still counts as ixfr.
pub(crate) async fn handle_tcp_query(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();
    let record_xfr_metric = |result| track_xfr(query.qtype, result);

    let signer = match authorize_transfer(query_data, client_ip, &query.zone_name).await {
        Ok(signer) => signer,
        Err(refusal) => {
            record_xfr_metric(XfrResult::Refused);
            log_warn!(
                "Refused XFR TCP query from {}: {}",
                client_ip,
                refusal.reason
            );
            // RFC 5936, Section 2.2.1: refuse with an RCODE, not a dropped
            // connection.
            let response = refusal.into_response(query)?;
            wire::write_tcp_message(stream, &response).await?;
            return Ok(());
        }
    };

    log_info!(
        "XFR TCP query: zone={:?}, qtype={:?}, from={}, signed={}",
        query.zone_name,
        query.qtype,
        client_ip,
        signer.is_some()
    );

    let result = match query.qtype {
        Rtype::AXFR => axfr::handle_axfr(stream, query, client_ip, Rtype::AXFR, signer).await,
        Rtype::IXFR => ixfr::handle_ixfr(stream, query, client_ip, signer).await,
        _ => {
            log_warn!("Unsupported query type: {:?}", query.qtype);
            return Err(XfrError::InvalidQuery(format!(
                "Unsupported query type: {:?}",
                query.qtype
            )));
        }
    };

    if let Err(err) = result {
        if matches!(err, XfrError::ZoneNotFound(_)) {
            record_xfr_metric(XfrResult::NotAuth);
            let response = query.error_response(Rcode::NOTAUTH);
            wire::write_tcp_message(stream, &response).await?;
            return Ok(());
        }

        record_xfr_metric(XfrResult::Error);
        return Err(err);
    }

    record_xfr_metric(XfrResult::Ok);
    Ok(())
}

/// Answer an XFR query received over UDP with TC set, so an allowed client
/// asks again over TCP; the caller checked the qtype. The truncated reply is
/// unsigned: the client re-asks over TCP and that answer carries the MAC.
pub(crate) async fn handle_udp_query(
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Vec<u8> {
    if let Err(refusal) = authorize_transfer(query_data, client_addr.ip(), &query.zone_name).await {
        track_xfr(query.qtype, XfrResult::Refused);
        log_warn!(
            "Refused XFR UDP query from {}: {}",
            client_addr.ip(),
            refusal.reason
        );
        return refusal
            .into_response(query)
            .unwrap_or_else(|_| query.error_response(Rcode::REFUSED));
    }
    // The transfer itself counts when the client returns over TCP.
    track_xfr(query.qtype, XfrResult::Truncated);
    query.truncated_response()
}
