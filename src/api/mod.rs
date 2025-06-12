mod controller;
mod dto;
pub mod service;

use crate::{config, log_error, log_info};
use controller::ApiController;
use std::net::SocketAddr;

pub async fn initialize() {
    let host = config::get_config::<String>("api.host");
    let port = config::get_config::<u16>("api.port");
    let ip_addr = match host.parse::<std::net::IpAddr>() {
        Ok(addr) => addr,
        Err(err) => {
            log_error!("Invalid host configuration: {}. Error: {:?}", host, err);
            return;
        }
    };
    let addr = SocketAddr::from((ip_addr, port));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    log_info!("Listening on http://{}", addr);

    axum::serve(listener, ApiController::routes().await)
        .await
        .unwrap_or_else(|err| {
            log_error!("Error serving connection: {:?}", err);
        });
}
