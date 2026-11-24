//! Virtual catalog membership and its persisted serial.

use bindizr_core::dns::name::ZoneName;
use bindizr_core::dns::{CatalogZone, Serial, SoaInterval, Ttl};
use bindizr_core::model::zone::Zone;
use ring::digest;
use ring::digest::SHA256;

use crate::error::ServiceError;
use crate::{Context, Transaction};

/// TTL used by the generated catalog's records.
const DEFAULT_TTL: Ttl = Ttl::from_secs(3600);

/// SOA REFRESH of the generated catalog, also bounding its NOTIFY batching delay.
pub(crate) const CATALOG_SOA_REFRESH: SoaInterval = SoaInterval::from_secs(3600);

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

/// Build the catalog from the enabled zones and advance its persisted serial
/// when their membership changed.
///
/// The catalog row is locked before the members are read, so overlapping
/// refreshes advance the serial in the order they saw membership.
pub(crate) async fn refresh_catalog_tx(
    tx: &mut Transaction<'_>,
    cx: &Context,
) -> Result<(CatalogZone, Vec<ZoneName>), ServiceError> {
    let config = cx.config();
    let catalog_zone_name = &config.dns.catalog_zone_name;
    log::info!("Generating catalog zone: {catalog_zone_name}");

    bindizr_db::catalog_zone::upsert_tx(tx, catalog_zone_name).await?;

    let zones: Vec<Zone> = bindizr_db::zone::list_all_tx(tx)
        .await?
        .into_iter()
        .filter(|zone| zone.enabled)
        .collect();

    let base_serial = zones
        .iter()
        .map(|zone| zone.serial)
        .max()
        .unwrap_or(Serial::from(1));

    // The catalog zone is not a member of itself.
    let member_zone_names: Vec<ZoneName> = zones
        .into_iter()
        .map(|zone| zone.name)
        .filter(|zone_name| zone_name != catalog_zone_name)
        .collect();

    log::info!(
        "Catalog zone contains {} member zones",
        member_zone_names.len()
    );

    // The catalog has its own serial row and no entry in the managed zones table.
    let digest = catalog_digest(&member_zone_names);
    let serial =
        bindizr_db::catalog_zone::update_tx(tx, catalog_zone_name, &digest, base_serial).await?;

    let catalog_zone = CatalogZone {
        name: catalog_zone_name.clone(),
        default_ttl: DEFAULT_TTL,
        serial,
        refresh: CATALOG_SOA_REFRESH,
        retry: SOA_RETRY,
        expire: SOA_EXPIRE,
        minimum_ttl: MINIMUM_TTL,
    };

    Ok((catalog_zone, member_zone_names))
}

/// Hash sorted member names so only membership changes advance the catalog serial.
/// Exclude member serials: record writes do not require catalog re-provisioning.
fn catalog_digest(member_zone_names: &[ZoneName]) -> String {
    // Names are canonical, so sorting needs no case folding.
    let mut zone_names: Vec<&ZoneName> = member_zone_names.iter().collect();
    zone_names.sort();

    let mut hasher = digest::Context::new(&SHA256);

    for zone_name in zone_names {
        hasher.update(zone_name.as_str().as_bytes());
        hasher.update(b"\n");
    }

    hex::encode(hasher.finish())
}

#[cfg(test)]
mod tests;
