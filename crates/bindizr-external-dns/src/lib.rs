//! ExternalDNS webhook provider adapter for bindizr: speaks the webhook
//! protocol on a localhost listener and forwards every operation to the
//! authenticated bindizr `/external-dns` API. All DNS logic and state stay
//! in the bindizr server.

mod config;
mod metrics;
mod server;
mod upstream;
mod wire;

use std::sync::Arc;

use bindizr_core::{log_error, log_info, logger};
use clap::Parser;

/// Parse arguments, start both listeners, and serve until interrupted.
pub async fn execute() {
    let cli = config::Cli::parse();
    let adapter_config = config::AdapterConfig::from_cli(cli).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });

    logger::initialize_with_level(adapter_config.log_level);

    if adapter_config.token.is_none() {
        log_error!(
            "no bindizr API token configured (--token or --token-file); requests will be unauthenticated"
        );
    }

    let upstream = upstream::UpstreamClient::new(
        adapter_config.bindizr_url.clone(),
        adapter_config.token,
        adapter_config.timeout_secs,
    )
    .unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });
    let state = Arc::new(server::AppState { upstream });

    let webhook_listener = tokio::net::TcpListener::bind(adapter_config.listen_addr)
        .await
        .unwrap_or_else(|e| {
            log_error!("Failed to bind {}: {:?}", adapter_config.listen_addr, e);
            std::process::exit(1);
        });
    let health_listener = tokio::net::TcpListener::bind(adapter_config.health_listen_addr)
        .await
        .unwrap_or_else(|e| {
            log_error!(
                "Failed to bind {}: {:?}",
                adapter_config.health_listen_addr,
                e
            );
            std::process::exit(1);
        });

    log_info!(
        "ExternalDNS webhook listening on http://{} (bindizr: {})",
        adapter_config.listen_addr,
        adapter_config.bindizr_url
    );
    log_info!(
        "Health endpoint listening on http://{}/healthz",
        adapter_config.health_listen_addr
    );

    let webhook = axum::serve(webhook_listener, server::webhook_router(state.clone()));
    let health = axum::serve(health_listener, server::health_router(state));

    tokio::select! {
        result = webhook => {
            if let Err(e) = result {
                log_error!("Webhook server error: {:?}", e);
            }
        }
        result = health => {
            if let Err(e) = result {
                log_error!("Health server error: {:?}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            log_info!("Shutting down");
        }
    }
}
