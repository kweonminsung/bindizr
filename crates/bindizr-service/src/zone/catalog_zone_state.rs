use crate::{error::ServiceError, repository::RepositoryService};

use super::ZoneService;

impl ZoneService {
    pub async fn update_catalog_serial_for_signature(
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<i32, ServiceError> {
        RepositoryService::update_catalog_serial_for_signature(name, signature, base_serial).await
    }
}
