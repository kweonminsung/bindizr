pub(crate) mod error;
pub(crate) mod middleware;
pub(crate) mod notify;
#[cfg(debug_assertions)]
pub(crate) mod openapi;
pub(crate) mod record;
pub(crate) mod router;
pub(crate) mod types;
pub(crate) mod zone;

use crate::{config, log_error, log_info};
use router::ApiRouter;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub(crate) async fn initialize() -> Result<(), String> {
    let bindizr_config = config::get_bindizr_config();
    let addr = SocketAddr::from((bindizr_config.listen_addr, bindizr_config.api.listen_port));

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        log_error!("Failed to bind to address {}: {:?}", addr, e);
        std::process::exit(1);
    });

    log_info!("HTTP API server listening on http://{}", addr);

    // Spawn API server in background
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, ApiRouter::routes().await).await {
            log_error!("API server error: {:?}", e);
        }
    });

    Ok(())
}
