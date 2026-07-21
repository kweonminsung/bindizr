//! Zone-transfer subsystem: dispatches AXFR/IXFR requests and drives NOTIFY,
//! SOA responses, and catalog-zone generation.

pub(crate) mod acl;
pub(crate) mod axfr;
pub(crate) mod catalog;
pub(crate) mod delta;
pub(crate) mod ixfr;
pub(crate) mod nsupdate;
pub(crate) mod soa;
pub(crate) mod zone_cache;

use std::net::{IpAddr, SocketAddr};

use catalog::generate_catalog_zone;
use domain::base::iana::Rtype;
use tokio::net::TcpStream;

use crate::{error::XfrError, log_info, log_warn, wire};

/// Initializes XFR support by ensuring the catalog zone exists.
pub async fn initialize() {
    ensure_catalog_zone().await;
}

async fn ensure_catalog_zone() {
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
pub fn is_xfr_query_type(qtype: Rtype) -> bool {
    matches!(qtype, Rtype::AXFR | Rtype::IXFR)
}

pub(crate) async fn handle_tcp_query(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    secondary_acl: &acl::SecondaryAcl,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();

    validate_secondary_acl(client_ip, secondary_acl).await?;

    let (zone_name, qtype, client_serial, query_id) = wire::parse_query(query_data)?;

    log_info!(
        "XFR TCP query: zone={:?}, qtype={:?}, from={}",
        zone_name.to_string(),
        qtype,
        client_ip
    );

    let result = match qtype {
        Rtype::AXFR => axfr::handle_axfr(stream, &zone_name, query_id, client_ip).await,
        Rtype::IXFR => {
            ixfr::handle_ixfr(stream, &zone_name, query_id, client_serial, client_ip).await
        }
        _ => {
            log_warn!("Unsupported query type: {:?}", qtype);
            return Err(XfrError::InvalidQuery(format!(
                "Unsupported query type: {:?}",
                qtype
            )));
        }
    };

    if let Err(err) = result {
        if matches!(err, XfrError::ZoneNotFound(_)) {
            let response = wire::build_error_response(
                query_id,
                &zone_name,
                qtype,
                crate::protocol::RCODE_NOTAUTH,
            );
            wire::write_tcp_message(stream, &response).await?;
            return Ok(());
        }

        return Err(err);
    }

    Ok(())
}

pub(crate) async fn handle_udp_query(
    client_addr: SocketAddr,
    secondary_acl: &acl::SecondaryAcl,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();

    validate_secondary_acl(client_ip, secondary_acl).await?;

    let (zone_name, qtype, _, _) = wire::parse_query(query_data)?;

    if is_xfr_query_type(qtype) {
        log_warn!(
            "XFR-like UDP query is not supported (zone={:?}, qtype={:?}, from={})",
            zone_name.to_string(),
            qtype,
            client_ip
        );

        return Err(XfrError::InvalidQuery(
            "XFR over UDP is not supported".to_string(),
        ));
    }

    Err(XfrError::InvalidQuery(format!(
        "Unsupported query type: {:?}",
        qtype
    )))
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
