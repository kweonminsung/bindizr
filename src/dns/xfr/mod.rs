pub mod axfr;
pub mod catalog;
pub mod delta;
pub mod error;
pub mod ixfr;
pub mod notify;
pub mod server;
pub mod wire;

use crate::{log_info, log_warn};
use catalog::generate_catalog_zone;

pub async fn initialize() {
    ensure_catalog_zone().await;
}

async fn ensure_catalog_zone() {
    match generate_catalog_zone().await {
        Ok((catalog, _members)) => {
            log_info!(
                "Catalog zone '{}' is ready (serial: {})",
                catalog::CATALOG_ZONE_NAME,
                catalog.serial
            );
        }
        Err(e) => {
            log_warn!("Failed to generate catalog zone: {}", e);
        }
    }
}
