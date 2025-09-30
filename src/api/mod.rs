pub mod controller;
pub mod service;

mod dto;

use crate::{config, log_error, log_info};
use controller::ApiController;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn initialize() -> Result<(), String> {
    let host = config::get_config::<String>("api.host");
    let port = config::get_config::<u16>("api.port");
    let ip_addr = host
        .parse::<std::net::IpAddr>()
        .map_err(|e| format!("Invalid host configuration: {}. Error: {:?}", host, e))?;

    let addr = SocketAddr::from((ip_addr, port));

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        log_error!("Failed to bind to address {}: {:?}", addr, e);
        std::process::exit(1);
    });

    log_info!("Listening on http://{}", addr);

    axum::serve(listener, ApiController::routes().await)
        .await
        .map_err(|e| format!("Error serving connection: {:?}", e))?;

    Ok(())
}
