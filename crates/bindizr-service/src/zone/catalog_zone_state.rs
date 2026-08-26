use super::ZoneService;
use crate::{error::ServiceError, repository::RepositoryService};

impl ZoneService {
    /// Advance the catalog zone serial when its content `digest` has changed;
    /// a no-op otherwise.
    pub async fn advance_catalog_serial(
        name: &str,
        digest: &str,
        base_serial: i32,
    ) -> Result<i32, ServiceError> {
        let mut tx = RepositoryService::begin_tx("Failed to update catalog state").await?;

        let apply_result =
            RepositoryService::upsert_catalog_zone_state_tx(&mut tx, name, digest, base_serial)
                .await;

        RepositoryService::finish_tx(tx, apply_result, "Failed to update catalog state").await
    }
}
