//! ExternalDNS webhook provider adapter for bindizr: speaks the webhook
//! protocol on a localhost listener and forwards every operation to the
//! authenticated bindizr `/external-dns` API. All DNS logic and state stay
//! in the bindizr server.

mod config;
mod metrics;
mod server;
mod upstream;
mod wire;

use std::{future::IntoFuture, sync::Arc, time::Duration};

use bindizr_core::logger;
use clap::Parser;
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::watch,
};

/// How long in-flight requests get once the adapter is asked to stop, bounded
/// well inside the grace period Kubernetes allows before SIGKILL.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The configuration is unusable, so a restart changes nothing — the code
/// bindizr's own CLI uses for that class.
const EXIT_CONFIG: i32 = 6;

/// Parse arguments, start both listeners, and serve until interrupted.
pub async fn execute() {
    let cli = config::Cli::parse();
    let adapter_config = config::AdapterConfig::from_cli(cli).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(EXIT_CONFIG);
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
        std::process::exit(EXIT_CONFIG);
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

    // Both servers watch one flag, so a signal or a failed server stops both.
    let (stop, _) = watch::channel(false);
    let webhook = axum::serve(webhook_listener, server::webhook_router(state.clone()))
        .with_graceful_shutdown(wait_for_stop(stop.subscribe()));
    let health = axum::serve(health_listener, server::health_router(state))
        .with_graceful_shutdown(wait_for_stop(stop.subscribe()));
    let mut webhook = tokio::spawn(webhook.into_future());
    let mut health = tokio::spawn(health.into_future());

    tokio::select! {
        result = &mut webhook => log_server_stopped("Webhook", result),
        result = &mut health => log_server_stopped("Health", result),
        () = wait_for_signal() => log::info!("Shutting down"),
    }

    // Answer what external-dns already sent before going: a severed reply
    // leaves it unable to tell an applied change from a dropped one.
    let _ = stop.send(true);
    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
        let _ = tokio::join!(webhook, health);
    })
    .await;
    if drained.is_err() {
        log::warn!(
            "In-flight requests did not finish within {}s; exiting anyway",
            DRAIN_TIMEOUT.as_secs()
        );
    }
}

/// Resolve once the adapter is asked to stop.
async fn wait_for_stop(mut stop: watch::Receiver<bool>) {
    while !*stop.borrow_and_update() {
        if stop.changed().await.is_err() {
            break;
        }
    }
}

/// Resolve on SIGTERM or SIGINT. PID 1 discards a signal it has no handler
/// for, and the adapter is PID 1 of its container, so without this a stopping
/// pod waits out its whole grace period.
async fn wait_for_signal() {
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(terminate) => terminate,
        Err(e) => {
            log::error!("Failed to listen for SIGTERM: {}", e);
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

/// Log the server that stopped on its own, which stops the adapter with it.
fn log_server_stopped(name: &str, result: Result<std::io::Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => log::error!("{} server stopped", name),
        Ok(Err(e)) => log::error!("{} server error: {:?}", name, e),
        Err(e) => log::error!("{} server task failed: {}", name, e),
    }
}
