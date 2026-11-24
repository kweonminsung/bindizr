//! Forward localhost ExternalDNS webhooks to the authenticated bindizr API.
//! DNS logic and state stay in the server.

mod config;
mod metrics;
mod server;
mod upstream;
mod wire;

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;
use std::{io, process};

use bindizr_core::config::{LogFormat, LoggingConfig};
use bindizr_core::errln;
use bindizr_core::logger::Logger;
use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal::unix::{self, Signal, SignalKind};
use tokio::sync::watch;
use tokio::sync::watch::Receiver;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time;

use crate::config::{AdapterConfig, Cli};
use crate::metrics::AdapterMetrics;
use crate::server::AppState;
use crate::upstream::UpstreamClient;

/// How long in-flight requests get once the adapter is asked to stop, bounded
/// well inside the grace period Kubernetes allows before SIGKILL.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The configuration is unusable, so a restart changes nothing — the code
/// bindizr's own CLI uses for that class.
const EXIT_CONFIG: i32 = 6;

/// Supervised adapter tasks paired with their names; `join_next` removes
/// finished tasks so shutdown never awaits a handle twice.
type Servers = JoinSet<(&'static str, Result<io::Result<()>, JoinError>)>;

/// Put a spawned listener under the adapter's supervision.
fn watch(servers: &mut Servers, name: &'static str, task: JoinHandle<io::Result<()>>) {
    servers.spawn(async move { (name, task.await) });
}

/// Parse arguments, start both listeners, and serve until interrupted.
pub async fn execute() {
    let cli = Cli::parse();
    let adapter_config = AdapterConfig::load(cli).unwrap_or_else(|error| {
        errln!("Error: {error}");
        process::exit(EXIT_CONFIG);
    });

    Logger::init(LoggingConfig {
        level: adapter_config.log_level,
        format: LogFormat::Text,
    });

    if adapter_config.token.is_none() {
        log::error!(
            "no bindizr API token configured (--token or --token-file); requests will be unauthenticated"
        );
    }

    // Prepare the upstream connection settings before accepting webhook requests.
    let upstream = UpstreamClient::new(
        adapter_config.bindizr_url.clone(),
        adapter_config.token,
        adapter_config.timeout_secs,
        adapter_config.ca_file.as_deref(),
    )
    .unwrap_or_else(|error| {
        errln!("Error: {error}");
        process::exit(EXIT_CONFIG);
    });
    let state = Arc::new(AppState {
        upstream,
        metrics: AdapterMetrics::new().unwrap_or_else(|error| {
            errln!("Error: {error}");
            process::exit(1);
        }),
    });

    // Bind both endpoints before either server starts accepting requests.
    let webhook_listener = TcpListener::bind(adapter_config.listen_addr)
        .await
        .unwrap_or_else(|error| {
            log::error!("Failed to bind {}: {error:?}", adapter_config.listen_addr);
            process::exit(1);
        });
    let health_listener = TcpListener::bind(adapter_config.health_listen_addr)
        .await
        .unwrap_or_else(|error| {
            log::error!(
                "Failed to bind {}: {error:?}",
                adapter_config.health_listen_addr
            );
            process::exit(1);
        });

    let listen = |signal, kind| {
        listen_for_signal(signal, kind).unwrap_or_else(|error| {
            log::error!("{error}");
            process::exit(1);
        })
    };
    let mut interrupt = listen("SIGINT", SignalKind::interrupt());
    let mut terminate = listen("SIGTERM", SignalKind::terminate());

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
    let stop = watch::channel(false).0;
    let webhook = axum::serve(webhook_listener, server::webhook_router(state.clone()))
        .with_graceful_shutdown(wait_for_stop(stop.subscribe()));
    let health = axum::serve(health_listener, server::health_router(state))
        .with_graceful_shutdown(wait_for_stop(stop.subscribe()));
    let mut servers = Servers::new();
    watch(&mut servers, "Webhook", tokio::spawn(webhook.into_future()));
    watch(&mut servers, "Health", tokio::spawn(health.into_future()));

    let failed = tokio::select! {
        Some(result) = servers.join_next() => {
            match result {
                Ok((name, result)) => log_server_stopped(name, result),
                Err(error) => log::error!("A server supervisor task failed: {error}"),
            }
            true
        }

        result = wait_for_signal(&mut interrupt, &mut terminate) => {
            match result {
                Ok(()) => log::info!("Shutting down"),
                Err(ref error) => log::error!("{error}"),
            }
            result.is_err()
        }
    };

    // Answer what external-dns already sent before going: a severed reply
    // leaves it unable to tell an applied change from a dropped one.
    let _ = stop.send(true);

    let drained = time::timeout(DRAIN_TIMEOUT, async {
        while let Some(result) = servers.join_next().await {
            match result {
                Ok((_, Ok(Ok(())))) => {}
                Ok((name, result)) => log_server_stopped(name, result),
                Err(error) => log::error!("A server supervisor task failed: {error}"),
            }
        }
    })
    .await;

    if drained.is_err() {
        log::warn!(
            "In-flight requests did not finish within {}s; exiting anyway",
            DRAIN_TIMEOUT.as_secs()
        );
    }

    // A listener stopping on its own is a failure, so a supervisor set to
    // restart only what failed brings the adapter back.
    if failed {
        process::exit(1);
    }
}

/// Resolve once the adapter is asked to stop.
async fn wait_for_stop(mut stop: Receiver<bool>) {
    while !*stop.borrow_and_update() {
        if stop.changed().await.is_err() {
            break;
        }
    }
}

/// Why an operating-system shutdown signal could not be observed.
#[derive(Debug, thiserror::Error)]
#[error("shutdown signal {signal} failed: {source}")]
struct SignalError {
    signal: &'static str,
    #[source]
    source: io::Error,
}

/// Register an operating-system signal, including when running as PID 1.
fn listen_for_signal(signal: &'static str, kind: SignalKind) -> Result<Signal, SignalError> {
    unix::signal(kind).map_err(|source| SignalError { signal, source })
}

/// Wait for an interrupt or termination signal, reporting closed receivers.
async fn wait_for_signal(
    interrupt: &mut Signal,
    terminate: &mut Signal,
) -> Result<(), SignalError> {
    let (signal, received) = tokio::select! {
        received = interrupt.recv() => ("SIGINT", received),
        received = terminate.recv() => ("SIGTERM", received),
    };

    received.ok_or_else(|| SignalError {
        signal,
        source: io::Error::new(io::ErrorKind::BrokenPipe, "signal listener closed"),
    })
}

/// Log the server that stopped on its own, which stops the adapter with it.
fn log_server_stopped(name: &str, result: Result<io::Result<()>, JoinError>) {
    match result {
        Ok(Ok(())) => log::error!("{name} server stopped"),
        Ok(Err(error)) => log::error!("{name} server error: {error:?}"),
        Err(error) => log::error!("{name} server task failed: {error}"),
    }
}
