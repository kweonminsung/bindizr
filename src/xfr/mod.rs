pub mod axfr;
pub mod catalog;
pub mod delta;
pub mod error;
pub mod ixfr;
pub mod server;
pub mod wire;

use crate::{log_error, log_info, log_warn};
use catalog::generate_catalog_zone;
use server::XfrServer;

pub async fn initialize() {
    ensure_catalog_zone().await;

    let xfr_server = XfrServer::new();

    tokio::spawn(async move {
        if let Err(e) = xfr_server.start().await {
            log_error!("XFR server error: {}", e);
        }
    });
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
