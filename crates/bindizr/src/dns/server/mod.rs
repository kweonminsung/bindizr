//! Inbound DNS serving: AXFR/IXFR dispatch with ACL gating, SOA responses,
//! catalog-zone generation, and RFC 2136 nsupdate handling.

use bindizr_core::dns::message;

pub(crate) mod acl;
pub(crate) mod axfr;
pub(crate) mod catalog;
pub(crate) mod ixfr;
pub(crate) mod nsupdate;
pub(crate) mod soa;
pub(crate) mod zone_cache;

use std::net::{IpAddr, SocketAddr};

use bindizr_core::{
    dns::message::{Rcode, Rtype},
    log_info, log_warn,
    metrics::metrics,
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
fn track_xfr(qtype: Rtype, result: &str) {
    let xfr_type = match qtype {
        Rtype::AXFR => "axfr",
        Rtype::IXFR => "ixfr",
        _ => return,
    };
    metrics()
        .xfr_total
        .with_label_values(&[xfr_type, result])
        .inc();
}

pub(crate) async fn handle_tcp_query(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    secondary_acl: &acl::SecondaryAcl,
    query: &message::ParsedQuery,
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();
    let record_xfr_metric = |result: &str| track_xfr(query.qtype, result);

    if let Err(err) = validate_secondary_acl(client_ip, secondary_acl).await {
        record_xfr_metric("refused");
        log_warn!("Refused XFR TCP query from {}: {}", client_ip, err);
        // RFC 5936, Section 2.2.1: refuse with an RCODE, not a dropped connection.
        let response = query.error_response(Rcode::REFUSED);
        wire::write_tcp_message(stream, &response).await?;
        return Ok(());
    }

    log_info!(
        "XFR TCP query: zone={:?}, qtype={:?}, from={}",
        query.zone_name,
        query.qtype,
        client_ip
    );

    let result = match query.qtype {
        Rtype::AXFR => axfr::handle_axfr(stream, query, client_ip, Rtype::AXFR).await,
        Rtype::IXFR => ixfr::handle_ixfr(stream, query, client_ip).await,
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
            record_xfr_metric("notauth");
            let response = query.error_response(Rcode::NOTAUTH);
            wire::write_tcp_message(stream, &response).await?;
            return Ok(());
        }

        record_xfr_metric("error");
        return Err(err);
    }

    record_xfr_metric("ok");
    Ok(())
}

/// Answer an XFR query received over UDP with TC set, so an allowed client
/// asks again over TCP; the caller checked the qtype.
pub(crate) async fn handle_udp_query(
    client_addr: SocketAddr,
    secondary_acl: &acl::SecondaryAcl,
    query: &message::ParsedQuery,
) -> Vec<u8> {
    if let Err(err) = validate_secondary_acl(client_addr.ip(), secondary_acl).await {
        track_xfr(query.qtype, "refused");
        log_warn!("Refused XFR UDP query from {}: {}", client_addr.ip(), err);
        return query.error_response(Rcode::REFUSED);
    }
    // The transfer itself counts when the client returns over TCP.
    track_xfr(query.qtype, "truncated");
    query.truncated_response()
}

async fn validate_secondary_acl(
    client_ip: IpAddr,
    secondary_acl: &acl::SecondaryAcl,
) -> Result<(), XfrError> {
    if !acl::is_client_allowed(client_ip, secondary_acl).await {
        return Err(XfrError::AccessDenied(format!(
            "IP {} is not a configured secondary",
            client_ip
        )));
    }

    Ok(())
}
