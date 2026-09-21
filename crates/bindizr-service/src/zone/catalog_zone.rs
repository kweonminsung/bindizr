use bindizr_core::config::bindizr_config;

use super::ZoneService;
use crate::{error::ServiceError, repository::RepositoryService};

impl ZoneService {
    /// Refuse to start while a stored zone holds the configured catalog zone
    /// name, which a write would be rejected for taking.
    pub async fn validate_catalog_zone_name() -> Result<(), ServiceError> {
        let name = &bindizr_config().dns.catalog_zone_name;
        if RepositoryService::get_zone_by_name(name).await?.is_some() {
            return Err(ServiceError::zone_conflict(format!(
                "zone '{}' has the name dns.catalog_zone_name gives the catalog; rename either one",
                name
            )));
        }
        Ok(())
    }

    /// Advance the catalog zone serial when its content `digest` has changed;
    /// a no-op otherwise.
    pub async fn advance_catalog_serial(
        name: &str,
        digest: &str,
        base_serial: i32,
    ) -> Result<i32, ServiceError> {
        let mut tx = RepositoryService::begin_tx("Failed to update catalog state").await?;

        let apply_result =
            RepositoryService::upsert_catalog_zone_tx(&mut tx, name, digest, base_serial).await;

        RepositoryService::finish_tx(tx, apply_result, "Failed to update catalog state").await
    }
}
