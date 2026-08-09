use super::ZoneService;
use crate::{error::ServiceError, repository::RepositoryService};

impl ZoneService {
    /// Bump the catalog zone serial only when its content `signature` has changed.
    pub async fn update_catalog_serial_for_signature(
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<i32, ServiceError> {
        let mut tx = RepositoryService::begin_tx("Failed to update catalog state").await?;

        let apply_result = RepositoryService::update_catalog_serial_for_signature_tx(
            &mut tx,
            name,
            signature,
            base_serial,
        )
        .await;

        RepositoryService::finish_tx(tx, apply_result, "Failed to update catalog state").await
    }
}
