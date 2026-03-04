pub mod controller;
pub mod dto;
pub mod error;
pub mod service;
pub mod validation;

use crate::{config, log_error, log_info};
use controller::ApiController;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn initialize() -> Result<(), String> {
    let listen_addr = config::get_config_optional::<String>("api.listen_addr")
        .unwrap_or_else(|| config::get_config::<String>("api.host"));
    let listen_port = config::get_config_optional::<u16>("api.listen_port")
        .unwrap_or_else(|| config::get_config::<u16>("api.port"));
    let ip_addr = listen_addr.parse::<std::net::IpAddr>().map_err(|e| {
        format!(
            "Invalid API listen address configuration: {}. Error: {:?}",
            listen_addr, e
        )
    })?;

    let addr = SocketAddr::from((ip_addr, listen_port));

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        log_error!("Failed to bind to address {}: {:?}", addr, e);
        std::process::exit(1);
    });

    log_info!("HTTP API server listening on http://{}", addr);

    axum::serve(listener, ApiController::routes().await)
        .await
        .map_err(|e| format!("Error serving connection: {:?}", e))?;

    Ok(())
}
