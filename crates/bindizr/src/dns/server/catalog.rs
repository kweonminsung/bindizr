use bindizr_core::{
    dns::{Serial, SoaInterval, Ttl, message, message::Rtype, tsig::TransferSigner},
    model::zone::{Zone, ZoneId},
};
use bindizr_service::zone;
use chrono::Utc;
use ring::digest::{Context, SHA256};

use crate::dns::{error::XfrError, server::DnsContext, stream::DnsStream};

/// Generates the catalog zone and its member zone list from `zones`, the
/// served zones loaded where the transfer was authorized.
pub(crate) async fn generate_catalog_zone(
    dns_cx: &DnsContext,
    zones: Vec<Zone>,
) -> Result<(Zone, Vec<String>), XfrError> {
    let cx = dns_cx.daemon();
    let config = cx.config();
    let catalog_zone_name = &config.dns.catalog_zone_name;
    log::info!("Generating catalog zone: {}", catalog_zone_name);

    let all_zones = zones;

    // The catalog zone is not a member of itself.
    let member_zones: Vec<String> = all_zones
        .iter()
        .map(|z| z.name.clone())
        .filter(|name| !config.dns.is_catalog_zone(name.as_str()))
        .map(|name| name.to_string())
        .collect();

    log::info!("Catalog zone contains {} member zones", member_zones.len());

    // The catalog zone is virtual (no DB row).
    let digest = catalog_digest(&member_zones);
    let base_serial = all_zones
        .iter()
        .map(|z| z.serial)
        .max()
        .unwrap_or(Serial::from(1));
    let serial = zone::advance_catalog_serial(cx, catalog_zone_name, &digest, base_serial).await?;

    let catalog_zone = Zone {
        id: ZoneId::from(0),
        name: catalog_zone_name.clone(),
        mname: "invalid".to_string(),
        rname: "invalid".to_string(),
        default_ttl: Ttl::from_secs(3600),
        serial,
        refresh: SoaInterval::from_secs(3600),
        retry: SoaInterval::from_secs(600),
        expire: SoaInterval::from_secs(86400),
        minimum_ttl: Ttl::from_secs(60),
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    };

    Ok((catalog_zone, member_zones))
}

/// Hash sorted member names so only membership changes advance the catalog serial.
/// Exclude member serials: record writes do not require catalog re-provisioning.
fn catalog_digest(member_zones: &[String]) -> String {
    // Names are canonical, so sorting needs no case folding.
    let mut members = member_zones.to_vec();
    members.sort();

    let mut hasher = Context::new(&SHA256);
    for member in members {
        hasher.update(member.as_bytes());
        hasher.update(b"\n");
    }

    hex::encode(hasher.finish())
}

/// Send a catalog zone transfer using the requested question type.
pub(crate) async fn handle_catalog_axfr(
    dns_cx: &DnsContext,
    stream: &mut DnsStream,
    query: &message::ParsedQuery,
    response_qtype: Rtype,
    signer: Option<TransferSigner>,
    zones: Vec<Zone>,
) -> Result<(), XfrError> {
    log::info!(
        "AXFR request for catalog zone: {}",
        dns_cx.daemon().config().dns.catalog_zone_name
    );

    // Materialize the virtual catalog from the current member zones.
    let (catalog_zone, member_zones) = generate_catalog_zone(dns_cx, zones).await?;

    let mut builder =
        message::DnsMessageBuilder::new(query.query_id, &query.qname, response_qtype, query.rd);
    if let Some(signer) = signer {
        builder = builder.sign_with(signer);
    }
    let mut messages_sent = 0usize;

    // Both SOAs must carry this snapshot's serial to delimit the AXFR.
    let serial = catalog_zone.serial;

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

    // Member PTRs tell secondaries which zones this catalog provisions.
    for member_zone in &member_zones {
        crate::dns::wire::add_answer_and_flush_if_needed(
            &mut builder,
            stream,
            &mut messages_sent,
            |builder| builder.add_catalog_ptr(&catalog_zone, member_zone),
        )
        .await?;
    }

    // Close the catalog snapshot before flushing its final envelope.
    crate::dns::wire::add_answer_and_flush_if_needed(
        &mut builder,
        stream,
        &mut messages_sent,
        |builder| builder.add_catalog_soa(&catalog_zone, serial),
    )
    .await?;
    messages_sent += crate::dns::wire::flush_if_not_empty(&mut builder, stream).await?;

    log::info!(
        "Catalog AXFR completed: sent {} member zones in {} DNS message(s)",
        member_zones.len(),
        messages_sent
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the catalog digest changes when members change and is
    /// indifferent to their order.
    #[test]
    fn catalog_digest_follows_membership_only() {
        let members = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();

        let original = catalog_digest(&members(&["example.com", "test.com"]));
        assert_ne!(original, catalog_digest(&members(&["example.com"])));
        // Order is not membership, so it must not read as a change.
        assert_eq!(
            original,
            catalog_digest(&members(&["test.com", "example.com"]))
        );
    }
}
