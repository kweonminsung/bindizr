//! Virtual catalog membership and its persisted serial.

use bindizr_core::{
    dns::{CATALOG_SOA_REFRESH, CatalogZone, Serial, SoaInterval, Ttl, name::ZoneName},
    model::zone::Zone,
};
use ring::digest::{self, SHA256};

use crate::{Context, error::ServiceError, transaction};

/// Refuse to start while a stored zone holds the configured catalog zone
/// name, which a write would be rejected for taking.
pub async fn validate_catalog_zone_name(cx: &Context) -> Result<(), ServiceError> {
    let name = &cx.config().dns.catalog_zone_name;

    if bindizr_db::zone::get_by_name(cx.db(), name)
        .await?
        .is_some()
    {
        return Err(ServiceError::zone_conflict(format!(
            "zone '{}' has the name dns.catalog_zone_name gives the catalog; rename either one",
            name
        )));
    }

    Ok(())
}

/// Advance the catalog zone serial when its content `digest` has changed;
/// a no-op otherwise.
async fn advance_catalog_serial(
    cx: &Context,
    name: &ZoneName,
    digest: &str,
    base_serial: Serial,
) -> Result<Serial, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to update catalog state").await?;

    let apply_result = bindizr_db::catalog_zone::upsert_tx(&mut tx, name, digest, base_serial)
        .await
        .map_err(ServiceError::from);

    transaction::finish_tx(tx, apply_result, "failed to update catalog state").await
}

/// TTL used by the generated catalog's records.
const DEFAULT_TTL: Ttl = Ttl::from_secs(3_600);

/// SOA retry interval of the generated catalog.
const SOA_RETRY: SoaInterval = SoaInterval::from_secs(600);

/// SOA expiry interval of the generated catalog.
const SOA_EXPIRE: SoaInterval = SoaInterval::from_secs(86_400);

/// Negative caching TTL of the generated catalog.
const MINIMUM_TTL: Ttl = Ttl::from_secs(60);

/// Refresh the catalog at startup from every enabled managed zone.
pub async fn refresh_catalog(cx: &Context) -> Result<(CatalogZone, Vec<String>), ServiceError> {
    refresh_catalog_from_zones(cx, super::list(cx).await?).await
}

/// Refresh the virtual catalog from supplied zones and persist its membership serial.
pub(crate) async fn refresh_catalog_from_zones(
    cx: &Context,
    zones: Vec<Zone>,
) -> Result<(CatalogZone, Vec<String>), ServiceError> {
    let config = cx.config();
    let catalog_zone_name = &config.dns.catalog_zone_name;
    log::info!("Generating catalog zone: {}", catalog_zone_name);

    let all_zones = zones;

    // The catalog zone is not a member of itself.
    let member_zones: Vec<String> = all_zones
        .iter()
        .map(|zone| zone.name.clone())
        .filter(|name| name != catalog_zone_name)
        .map(|name| name.to_string())
        .collect();

    log::info!("Catalog zone contains {} member zones", member_zones.len());

    // The catalog zone is virtual (no DB row).
    let digest = catalog_digest(&member_zones);
    let base_serial = all_zones
        .iter()
        .map(|zone| zone.serial)
        .max()
        .unwrap_or(Serial::from(1));

    let serial = advance_catalog_serial(cx, catalog_zone_name, &digest, base_serial).await?;

    let catalog_zone = CatalogZone {
        name: catalog_zone_name.clone(),
        default_ttl: DEFAULT_TTL,
        serial,
        refresh: CATALOG_SOA_REFRESH,
        retry: SOA_RETRY,
        expire: SOA_EXPIRE,
        minimum_ttl: MINIMUM_TTL,
    };

    Ok((catalog_zone, member_zones))
}

/// Hash sorted member names so only membership changes advance the catalog serial.
/// Exclude member serials: record writes do not require catalog re-provisioning.
fn catalog_digest(member_zones: &[String]) -> String {
    // Names are canonical, so sorting needs no case folding.
    let mut members = member_zones.to_vec();
    members.sort();

    let mut hasher = digest::Context::new(&SHA256);

    for member in members {
        hasher.update(member.as_bytes());
        hasher.update(b"\n");
    }

    hex::encode(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the catalog digest changes when members change and is
    /// indifferent to their order.
    #[test]
    fn catalog_digest_changes_only_with_membership() {
        let members = |names: &[&str]| names.iter().map(ToString::to_string).collect::<Vec<_>>();

        let original = catalog_digest(&members(&["example.com", "test.com"]));

        assert_ne!(original, catalog_digest(&members(&["example.com"])));

        // Order is not membership, so it must not read as a change.
        assert_eq!(
            original,
            catalog_digest(&members(&["test.com", "example.com"]))
        );
    }
}
