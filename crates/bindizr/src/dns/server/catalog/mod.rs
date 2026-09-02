use std::collections::HashMap;

pub(crate) use bindizr_core::dns::{CATALOG_ZONE_NAME, is_catalog_zone};
use bindizr_core::{
    dns::{message, message::Rtype, name::ZoneName},
    log_info,
    model::zone::{DnssecDenial, Zone},
};
use bindizr_service::zone::ZoneService;
use chrono::Utc;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

use crate::dns::error::XfrError;

/// Generates the catalog zone and its member zone list.
pub(crate) async fn generate_catalog_zone() -> Result<(Zone, Vec<String>), XfrError> {
    log_info!("Generating catalog zone: {}", CATALOG_ZONE_NAME);

    let all_zones = ZoneService::list().await?;

    // The catalog zone is not a member of itself.
    let member_zones: Vec<String> = all_zones
        .iter()
        .map(|z| z.name.clone())
        .filter(|name| name.as_str() != CATALOG_ZONE_NAME)
        .map(|name| name.to_string())
        .collect();

    log_info!("Catalog zone contains {} member zones", member_zones.len());

    // The catalog zone is virtual (no DB row).
    let serial = generate_catalog_serial(&member_zones, &all_zones).await?;

    let catalog_zone = Zone {
        id: 0,
        name: ZoneName::from_row(CATALOG_ZONE_NAME),
        mname: "invalid".to_string(),
        rname: "invalid".to_string(),
        default_ttl: 3600,
        serial,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum_ttl: 60,
        dnssec_denial: DnssecDenial::Nsec,
        dnssec_signature_validity_days: None,
        dnssec_signature_refresh_days: None,
        dnssec_zsk_lifetime_days: None,
        created_at: Utc::now(),
    };

    Ok((catalog_zone, member_zones))
}

async fn generate_catalog_serial(member_zones: &[String], zones: &[Zone]) -> Result<i32, XfrError> {
    let digest = catalog_digest(member_zones, zones);
    let base_serial = zones.iter().map(|z| z.serial).max().unwrap_or(1);
    Ok(ZoneService::advance_catalog_serial(CATALOG_ZONE_NAME, &digest, base_serial).await?)
}

fn catalog_digest(member_zones: &[String], zones: &[Zone]) -> String {
    // Index serials by lowercased name so the per-member lookup is O(1).
    let serial_by_name: HashMap<String, i32> = zones
        .iter()
        .map(|z| (z.name.to_string(), z.serial))
        .collect();

    let mut members = member_zones
        .iter()
        .map(|member| member.to_ascii_lowercase())
        .collect::<Vec<_>>();
    members.sort();

    let mut hasher = Sha256::new();
    for member in members {
        if let Some(serial) = serial_by_name.get(&member) {
            hasher.update(member.as_bytes());
            hasher.update(b"\0");
            hasher.update(serial.to_string().as_bytes());
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
    query: &message::ParsedQuery,
    response_qtype: Rtype,
) -> Result<(), XfrError> {
    log_info!("AXFR request for catalog zone: {}", CATALOG_ZONE_NAME);

    let (catalog_zone, member_zones) = generate_catalog_zone().await?;

    let mut builder = message::DnsMessageBuilder::new(query.query_id, &query.qname, response_qtype);
    let mut messages_sent = 0usize;
    let serial = bindizr_core::dns::serial_to_u32(catalog_zone.serial)?;

    crate::dns::wire::add_answer_and_flush_if_needed(
        &mut builder,
        stream,
        &mut messages_sent,
        |builder| builder.add_catalog_soa(&catalog_zone, serial),
    )
    .await?;

    crate::dns::wire::add_answer_and_flush_if_needed(
        &mut builder,
        stream,
        &mut messages_sent,
        |builder| builder.add_catalog_ns(&catalog_zone),
    )
    .await?;
    crate::dns::wire::add_answer_and_flush_if_needed(
        &mut builder,
        stream,
        &mut messages_sent,
        |builder| builder.add_catalog_schema_version(&catalog_zone),
    )
    .await?;

    for member_zone in &member_zones {
        crate::dns::wire::add_answer_and_flush_if_needed(
            &mut builder,
            stream,
            &mut messages_sent,
            |builder| builder.add_catalog_ptr(&catalog_zone, member_zone),
        )
        .await?;
    }

    crate::dns::wire::add_answer_and_flush_if_needed(
        &mut builder,
        stream,
        &mut messages_sent,
        |builder| builder.add_catalog_soa(&catalog_zone, serial),
    )
    .await?;
    messages_sent += crate::dns::wire::flush_if_not_empty(&mut builder, stream).await?;

    log_info!(
        "Catalog AXFR completed: sent {} member zones in {} DNS message(s)",
        member_zones.len(),
        messages_sent
    );

    Ok(())
}

#[cfg(test)]
mod tests;
