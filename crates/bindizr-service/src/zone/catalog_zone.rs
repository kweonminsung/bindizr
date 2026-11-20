//! Virtual catalog membership and its persisted serial.

use bindizr_core::dns::{CATALOG_SOA_REFRESH, CatalogZone, Serial, SoaInterval, Ttl};
use bindizr_core::model::zone::Zone;
use bindizr_db::LockLevel;
use ring::digest;
use ring::digest::SHA256;

use crate::error::ServiceError;
use crate::{Context, Transaction, transaction};

/// TTL used by the generated catalog's records.
const DEFAULT_TTL: Ttl = Ttl::from_secs(3600);

/// SOA retry interval of the generated catalog.
const SOA_RETRY: SoaInterval = SoaInterval::from_secs(600);

/// SOA expiry interval of the generated catalog.
const SOA_EXPIRE: SoaInterval = SoaInterval::from_secs(86400);

/// Negative caching TTL of the generated catalog.
const MINIMUM_TTL: Ttl = Ttl::from_secs(60);

/// Refuse to start while a stored zone holds the configured catalog zone
/// name, which a write would be rejected for taking.
pub async fn validate_catalog_zone_name(cx: &Context) -> Result<(), ServiceError> {
    let catalog_zone_name = &cx.config().dns.catalog_zone_name;

    if bindizr_db::zone::get_by_name(cx.db(), catalog_zone_name)
        .await?
        .is_some()
    {
        return Err(ServiceError::zone_conflict(format!(
            "zone '{catalog_zone_name}' has the name dns.catalog_zone_name gives the catalog; rename either one"
        )));
    }

    Ok(())
}

/// Refresh the catalog at startup from every enabled managed zone.
pub async fn refresh_catalog(cx: &Context) -> Result<(CatalogZone, Vec<String>), ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to update catalog state").await?;

    let refresh_result = refresh_catalog_tx(&mut tx, cx).await;

    transaction::finish_tx(tx, refresh_result, "failed to update catalog state").await
}

/// Build the catalog from the enabled zones and advance its persisted serial
/// when their membership changed.
///
/// The catalog row is locked before the members are read, so overlapping
/// refreshes advance the serial in the order they saw membership.
pub(crate) async fn refresh_catalog_tx(
    tx: &mut Transaction<'_>,
    cx: &Context,
) -> Result<(CatalogZone, Vec<String>), ServiceError> {
    let config = cx.config();
    let catalog_zone_name = &config.dns.catalog_zone_name;
    log::info!("Generating catalog zone: {catalog_zone_name}");

    // Read only for its row lock; the serial served comes from the upsert below.
    bindizr_db::catalog_zone::find_serial_tx(tx, catalog_zone_name, LockLevel::Exclusive).await?;

    let zones: Vec<Zone> = bindizr_db::zone::list_all_tx(tx, LockLevel::Unlocked)
        .await?
        .into_iter()
        .filter(|zone| zone.enabled)
        .collect();

    // The catalog zone is not a member of itself.
    let member_zones: Vec<String> = zones
        .iter()
        .map(|zone| &zone.name)
        .filter(|zone_name| *zone_name != catalog_zone_name)
        .map(ToString::to_string)
        .collect();

    log::info!("Catalog zone contains {} member zones", member_zones.len());

    // The catalog zone is virtual (no DB row).
    let digest = catalog_digest(&member_zones);
    let base_serial = zones
        .iter()
        .map(|zone| zone.serial)
        .max()
        .unwrap_or(Serial::from(1));

    let serial =
        bindizr_db::catalog_zone::upsert_tx(tx, catalog_zone_name, &digest, base_serial).await?;

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
