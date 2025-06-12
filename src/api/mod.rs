mod controller;
mod dto;
pub mod service;

use crate::{config, log_error, log_info};
use controller::ApiController;
use std::net::SocketAddr;

pub async fn initialize() {
    let host = config::get_config::<String>("api.host");
    let port = config::get_config::<u16>("api.port");
    let addr = SocketAddr::from((host.parse::<std::net::IpAddr>().unwrap(), port));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    log_info!("Listening on http://{}", addr);

    axum::serve(listener, ApiController::routes().await)
        .await
        .unwrap_or_else(|err| {
            log_error!("Error serving connection: {:?}", err);
        });
}
