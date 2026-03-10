use super::{error::XfrError, wire};
use crate::{
    database::{get_zone_repository, model::zone::Zone},
    log_info,
};
use chrono::Utc;
use domain::base::{Name, iana::Rtype};
use tokio::net::TcpStream;

pub const CATALOG_ZONE_NAME: &str = "catalog.bind";

/// Generate the catalog zone and its member list
pub async fn generate_catalog_zone() -> Result<(Zone, Vec<String>), XfrError> {
    log_info!("Generating catalog zone: {}", CATALOG_ZONE_NAME);

    let zone_repo = get_zone_repository();
    let all_zones = zone_repo
        .get_all()
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    // Filter out catalog zone itself
    let member_zones: Vec<String> = all_zones
        .iter()
        .map(|z| z.name.clone())
        .filter(|name| name != CATALOG_ZONE_NAME)
        .collect();

    log_info!("Catalog zone contains {} member zones", member_zones.len());

    // Create catalog zone metadata. This is a virtual zone
    let catalog_zone = Zone {
        id: 0, // Virtual zone ID
        name: CATALOG_ZONE_NAME.to_string(),
        primary_ns: "invalid".to_string(),
        primary_ns_ip: None,
        primary_ns_ipv6: None,
        admin_email: "invalid".to_string(),
        ttl: 3600,
        serial: generate_catalog_serial(&all_zones),
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum_ttl: 60,
        created_at: Utc::now(),
    };

    Ok((catalog_zone, member_zones))
}

fn generate_catalog_serial(zones: &[Zone]) -> i32 {
    zones.iter().map(|z| z.serial).max().unwrap_or(1)
}

pub async fn handle_catalog_axfr_with_qtype(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    response_qtype: Rtype,
) -> Result<(), XfrError> {
    log_info!("AXFR request for catalog zone: {}", CATALOG_ZONE_NAME);

    let (catalog_zone, member_zones) = generate_catalog_zone().await?;

    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, response_qtype);
    builder.add_soa(&catalog_zone, catalog_zone.serial as u32)?;

    builder.add_catalog_ns(&catalog_zone)?;
    builder.add_catalog_version(&catalog_zone)?;

    let primary_ip = crate::config::get_config_optional::<String>("advertised_addr")
        .unwrap_or_else(|| "127.0.0.1".to_string());

    for zone_name in &member_zones {
        builder.add_catalog_ptr(&catalog_zone, zone_name)?;
        builder.add_catalog_primaries(&catalog_zone, zone_name, &primary_ip)?;
    }

    builder.add_soa(&catalog_zone, catalog_zone.serial as u32)?;

    let message = builder.build();
    wire::write_tcp_message(stream, &message).await?;

    log_info!(
        "Catalog AXFR completed: sent {} member zones",
        member_zones.len()
    );

    Ok(())
}

pub fn is_catalog_zone(zone_name: &str) -> bool {
    zone_name == CATALOG_ZONE_NAME
}

pub fn zone_name_to_member_id(zone_name: &str) -> String {
    zone_name.replace('.', "-")
}

/// Handle SOA query for catalog zone
pub async fn handle_catalog_soa(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
) -> Result<(), XfrError> {
    log_info!("SOA query for catalog zone: {}", CATALOG_ZONE_NAME);

    let (catalog_zone, _member_zones) = generate_catalog_zone().await?;

    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, Rtype::SOA);
    builder.add_soa(&catalog_zone, catalog_zone.serial as u32)?;

    let message = builder.build();
    wire::write_tcp_message(stream, &message).await?;

    log_info!("Catalog SOA response sent: serial {}", catalog_zone.serial);

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_catalog_zone() {
        assert!(is_catalog_zone("catalog.bind"));
        assert!(!is_catalog_zone("example.com"));
        assert!(!is_catalog_zone("catalog.example.com"));
    }

    #[test]
    fn test_zone_name_to_member_id() {
        assert_eq!(zone_name_to_member_id("example.com"), "example-com");
        assert_eq!(zone_name_to_member_id("api.example.com"), "api-example-com");
        assert_eq!(zone_name_to_member_id("test.co.uk"), "test-co-uk");
    }

    #[test]
    fn test_generate_catalog_serial() {
        let zones = vec![
            Zone {
                id: 1,
                name: "example.com".to_string(),
                primary_ns: "ns1.example.com".to_string(),
                primary_ns_ip: None,
                primary_ns_ipv6: None,
                admin_email: "admin.example.com".to_string(),
                ttl: 3600,
                serial: 100,
                refresh: 3600,
                retry: 3600,
                expire: 604800,
                minimum_ttl: 3600,
                created_at: Utc::now(),
            },
            Zone {
                id: 2,
                name: "test.com".to_string(),
                primary_ns: "ns1.test.com".to_string(),
                primary_ns_ip: None,
                primary_ns_ipv6: None,
                admin_email: "admin.test.com".to_string(),
                ttl: 3600,
                serial: 200,
                refresh: 3600,
                retry: 3600,
                expire: 604800,
                minimum_ttl: 3600,
                created_at: Utc::now(),
            },
        ];

        assert_eq!(generate_catalog_serial(&zones), 200);
    }
}
