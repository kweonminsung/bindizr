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

use bindizr_core::logger;
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
        log::error!(
            "no bindizr API token configured (--token or --token-file); requests will be unauthenticated"
        );
    }

    // Prepare the upstream connection settings before accepting webhook requests.
    let upstream = upstream::UpstreamClient::new(
        adapter_config.bindizr_url.clone(),
        adapter_config.token,
        adapter_config.timeout_secs,
        adapter_config.ca_file.as_deref(),
    )
    .unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });
    let state = Arc::new(server::AppState { upstream });

    // Bind both endpoints before either server starts accepting requests.
    let webhook_listener = tokio::net::TcpListener::bind(adapter_config.listen_addr)
        .await
        .unwrap_or_else(|e| {
            log::error!("Failed to bind {}: {:?}", adapter_config.listen_addr, e);
            std::process::exit(1);
        });
    let health_listener = tokio::net::TcpListener::bind(adapter_config.health_listen_addr)
        .await
        .unwrap_or_else(|e| {
            log::error!(
                "Failed to bind {}: {:?}",
                adapter_config.health_listen_addr,
                e
            );
            std::process::exit(1);
        });

    log::info!(
        "ExternalDNS webhook listening on http://{} (bindizr: {})",
        adapter_config.listen_addr,
        adapter_config.bindizr_url
    );
    log::info!(
        "Health endpoint listening on http://{}/healthz",
        adapter_config.health_listen_addr
    );

    let webhook = axum::serve(webhook_listener, server::webhook_router(state.clone()));
    let health = axum::serve(health_listener, server::health_router(state));

    // Stop the adapter when either server exits or an interrupt arrives.
    tokio::select! {
        result = webhook => {
            if let Err(e) = result {
                log::error!("Webhook server error: {:?}", e);
            }
        }
        result = health => {
            if let Err(e) = result {
                log::error!("Health server error: {:?}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            log::info!("Shutting down");
        }
    }
}
