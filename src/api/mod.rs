pub mod service;

mod controller;
mod dto;

use crate::{config, log_info};
use controller::ApiController;
use once_cell::sync::OnceCell;
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::Notify};

static SHUTDOWN_NOTIFY: OnceCell<Arc<Notify>> = OnceCell::new();

pub async fn initialize() -> Result<(), String> {
    let host = config::get_config::<String>("api.host");
    let port = config::get_config::<u16>("api.port");
    let ip_addr = host
        .parse::<std::net::IpAddr>()
        .map_err(|e| format!("Invalid host configuration: {}. Error: {:?}", host, e))?;

    let addr = SocketAddr::from((ip_addr, port));

    let listener = TcpListener::bind(addr).await.unwrap();

    log_info!("Listening on http://{}", addr);

    // Generate a shutdown notification
    let notify = Arc::new(Notify::new());
    SHUTDOWN_NOTIFY.set(notify.clone()).ok();

    axum::serve(listener, ApiController::routes().await)
        .with_graceful_shutdown(async move {
            notify.notified().await;
        })
        .await
        .map_err(|e| format!("Error serving connection: {:?}", e))?;

    Ok(())
}

pub fn shutdown() {
    log_info!("Shutting down API server");

    if let Some(notify) = SHUTDOWN_NOTIFY.get() {
        notify.notify_one();
    }
}
