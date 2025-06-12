mod controller;
mod dto;
pub mod service;

use crate::{config, log_info};
use controller::ApiController;
use std::net::SocketAddr;

pub async fn initialize() -> Result<(), String> {
    let host = config::get_config::<String>("api.host");
    let port = config::get_config::<u16>("api.port");
    let ip_addr = host
        .parse::<std::net::IpAddr>()
        .map_err(|e| format!("Invalid host configuration: {}. Error: {:?}", host, e))?;

    let addr = SocketAddr::from((ip_addr, port));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    log_info!("Listening on http://{}", addr);

    axum::serve(listener, ApiController::routes().await)
        .await
        .map_err(|e| format!("Error serving connection: {:?}", e))?;

    Ok(())
}
