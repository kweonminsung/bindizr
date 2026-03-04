pub mod axfr;
pub mod delta;
pub mod error;
pub mod ixfr;
pub mod server;
pub mod wire;

use server::XfrServer;

/// Initialize and start XFR server in background
pub async fn initialize() {
    let xfr_server = XfrServer::new();
    
    // Spawn XFR server in background task
    tokio::spawn(async move {
        if let Err(e) = xfr_server.start().await {
            eprintln!("XFR server error: {}", e);
        }
    });
}
