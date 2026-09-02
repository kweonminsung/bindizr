//! Inbound zone transfers. The service decides when a zone is fetched and
//! from whom; the DNS I/O is the binary's, injected like the NOTIFY sender.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

#[async_trait]
pub trait ZoneTransferClient: Send + Sync {
    /// Transfer the zone from `server` (`host[:port]`, port 53 default) and
    /// render it as zone-file text ready for the import parser.
    async fn fetch_zone_file(&self, server: &str, zone_name: &str) -> Result<String, String>;
}

static ZONE_TRANSFER_CLIENT: OnceLock<Arc<dyn ZoneTransferClient>> = OnceLock::new();

/// Register the global transfer client; fails if one is already registered.
pub fn set_zone_transfer_client(client: Arc<dyn ZoneTransferClient>) -> Result<(), &'static str> {
    ZONE_TRANSFER_CLIENT
        .set(client)
        .map_err(|_| "zone transfer client is already registered")
}

/// Fetch `zone_name` from `server` via the registered client.
pub(crate) async fn fetch_zone_file(server: &str, zone_name: &str) -> Result<String, String> {
    match ZONE_TRANSFER_CLIENT.get() {
        Some(client) => client.fetch_zone_file(server, zone_name).await,
        None => Err("zone transfer client is not registered".to_string()),
    }
}
