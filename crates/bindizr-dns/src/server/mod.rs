//! Inbound DNS serving: AXFR/IXFR dispatch with ACL gating, SOA responses,
//! catalog-zone generation, and RFC 2136 nsupdate handling.

use bindizr_core::dns::message;

pub(crate) mod acl;
pub(crate) mod axfr;
pub(crate) mod catalog;
pub(crate) mod delta;
pub(crate) mod ixfr;
pub(crate) mod nsupdate;
pub(crate) mod soa;
pub(crate) mod zone_cache;

use std::net::{IpAddr, SocketAddr};

use bindizr_core::dns::message::{Rcode, Rtype};
use catalog::generate_catalog_zone;
use tokio::net::TcpStream;

use crate::{error::XfrError, log_info, log_warn, metrics::metrics, wire};

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

/// Returns `true` if `qtype` is a zone-transfer query (AXFR or IXFR).
pub(crate) fn is_xfr_query_type(qtype: Rtype) -> bool {
    matches!(qtype, Rtype::AXFR | Rtype::IXFR)
}

pub(crate) async fn handle_tcp_query(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    secondary_acl: &acl::SecondaryAcl,
    query: &message::ParsedQuery,
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();

    // Counted at the dispatch so IXFR that internally falls back to AXFR
    // still counts as ixfr; non-XFR qtypes are not transfer traffic.
    let xfr_type = match query.qtype {
        Rtype::AXFR => Some("axfr"),
        Rtype::IXFR => Some("ixfr"),
        _ => None,
    };
    let record_xfr_metric = |result: &str| {
        if let Some(xfr_type) = xfr_type {
            metrics()
                .xfr_total
                .with_label_values(&[xfr_type, result])
                .inc();
        }
    };

    if let Err(err) = validate_secondary_acl(client_ip, secondary_acl).await {
        record_xfr_metric("refused");
        return Err(err);
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

/// Rejects an XFR query received over UDP; the caller checked the qtype.
pub(crate) async fn handle_udp_query(
    client_addr: SocketAddr,
    secondary_acl: &acl::SecondaryAcl,
    query: &message::ParsedQuery,
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();

    validate_secondary_acl(client_ip, secondary_acl).await?;

    log_warn!(
        "XFR-like UDP query is not supported (zone={:?}, qtype={:?}, from={})",
        query.zone_name,
        query.qtype,
        client_ip
    );

    Err(XfrError::InvalidQuery(
        "XFR over UDP is not supported".to_string(),
    ))
}

async fn validate_secondary_acl(
    client_ip: IpAddr,
    secondary_acl: &acl::SecondaryAcl,
) -> Result<(), XfrError> {
    if !acl::is_client_allowed(client_ip, secondary_acl).await {
        log_warn!(
            "XFR request denied from {} (not a configured secondary server)",
            client_ip
        );
        return Err(XfrError::AccessDenied(format!(
            "IP {} not allowed",
            client_ip
        )));
    }

    Ok(())
}
