use super::{error::XfrError, wire};
use crate::{log_info, model::zone::Zone, service::zone::ZoneService};
use chrono::Utc;
use domain::base::{Name, iana::Rtype};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

pub(crate) const CATALOG_ZONE_NAME: &str = "catalog.bind";

/// Generate the catalog zone and its member list
pub(crate) async fn generate_catalog_zone() -> Result<(Zone, Vec<String>), XfrError> {
    log_info!("Generating catalog zone: {}", CATALOG_ZONE_NAME);

    let all_zones = ZoneService::list()
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
    let serial = generate_catalog_serial(&member_zones, &all_zones).await?;

    let catalog_zone = Zone {
        id: 0, // Virtual zone ID
        name: CATALOG_ZONE_NAME.to_string(),
        primary_ns: "invalid".to_string(),
        admin_email: "invalid".to_string(),
        ttl: 3600,
        serial,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum_ttl: 60,
        created_at: Utc::now(),
    };

    Ok((catalog_zone, member_zones))
}

async fn generate_catalog_serial(member_zones: &[String], zones: &[Zone]) -> Result<i32, XfrError> {
    let signature = catalog_signature(member_zones, zones);
    let base_serial = zones.iter().map(|z| z.serial).max().unwrap_or(1);
    ZoneService::update_catalog_serial_for_signature(CATALOG_ZONE_NAME, &signature, base_serial)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))
}

fn catalog_signature(member_zones: &[String], zones: &[Zone]) -> String {
    let mut members = member_zones
        .iter()
        .map(|member| member.to_ascii_lowercase())
        .collect::<Vec<_>>();
    members.sort();

    let mut hasher = Sha256::new();
    for member in members {
        if let Some(zone) = zones.iter().find(|z| z.name.eq_ignore_ascii_case(&member)) {
            hasher.update(member.as_bytes());
            hasher.update(b"\0");
            hasher.update(zone.serial.to_string().as_bytes());
            hasher.update(b"\n");
        }
    }

    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

pub(crate) async fn handle_catalog_axfr_with_qtype(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    response_qtype: Rtype,
) -> Result<(), XfrError> {
    log_info!("AXFR request for catalog zone: {}", CATALOG_ZONE_NAME);

    let (catalog_zone, member_zones) = generate_catalog_zone().await?;

    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, response_qtype);
    let mut messages_sent = 0usize;

    messages_sent += wire::add_answer_and_flush_if_needed(stream, &mut builder, |builder| {
        builder.add_catalog_soa(&catalog_zone, catalog_zone.serial as u32)
    })
    .await?;

    messages_sent += wire::add_answer_and_flush_if_needed(stream, &mut builder, |builder| {
        builder.add_catalog_ns(&catalog_zone)
    })
    .await?;
    messages_sent += wire::add_answer_and_flush_if_needed(stream, &mut builder, |builder| {
        builder.add_catalog_version(&catalog_zone)
    })
    .await?;

    for member_zone in &member_zones {
        messages_sent += wire::add_answer_and_flush_if_needed(stream, &mut builder, |builder| {
            builder.add_catalog_ptr(&catalog_zone, member_zone)
        })
        .await?;
    }

    messages_sent += wire::add_answer_and_flush_if_needed(stream, &mut builder, |builder| {
        builder.add_catalog_soa(&catalog_zone, catalog_zone.serial as u32)
    })
    .await?;
    messages_sent += wire::flush_message_if_not_empty(stream, &mut builder).await?;

    log_info!(
        "Catalog AXFR completed: sent {} member zones in {} DNS message(s)",
        member_zones.len(),
        messages_sent
    );

    Ok(())
}

pub(crate) fn is_catalog_zone(zone_name: &str) -> bool {
    zone_name == CATALOG_ZONE_NAME
}

pub(crate) fn zone_name_to_member_id(zone_name: &str) -> String {
    zone_name.replace('.', "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_catalog_zone_matches_catalog_bind() {
        assert!(is_catalog_zone("catalog.bind"));
        assert!(!is_catalog_zone("example.com"));
        assert!(!is_catalog_zone("catalog.example.com"));
    }

    #[test]
    fn zone_name_to_member_id_is_stable_and_dns_safe() {
        assert_eq!(zone_name_to_member_id("example.com"), "example-com");
        assert_eq!(zone_name_to_member_id("api.example.com"), "api-example-com");
        assert_eq!(zone_name_to_member_id("test.co.uk"), "test-co-uk");
    }

    #[test]
    fn catalog_signature_changes_when_members_change() {
        let zones = vec![
            Zone {
                id: 1,
                name: "example.com".to_string(),
                primary_ns: "ns1.example.com".to_string(),
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

        let member_zones = zones
            .iter()
            .map(|zone| zone.name.clone())
            .collect::<Vec<_>>();
        let original = catalog_signature(&member_zones, &zones);
        let updated_members = vec!["example.com".to_string()];

        assert_ne!(original, catalog_signature(&updated_members, &zones));
    }
}
