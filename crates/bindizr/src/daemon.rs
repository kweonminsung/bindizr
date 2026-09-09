//! The daemon runtime: wiring the process together, serving until asked to
//! stop, and re-executing itself on restart. The CLI only decides when to
//! start it.

use std::time::Duration;

use bindizr_core::{config, log_error, log_info, logger};
use bindizr_db as database;
use bindizr_service as service;
use tokio::signal::unix::{SignalKind, signal};

use crate::{api, dns, shutdown::Shutdown, socket};

/// How long the servers that can finish on their own get before the daemon
/// exits anyway.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Re-exec path captured at startup: after a package upgrade /proc/self/exe
/// reads as a "(deleted)" path, while this path points at the replacement.
static DAEMON_EXE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Initialize config, logging, database, DNS, socket, and API servers, then run until Ctrl+C.
pub(crate) async fn bootstrap(config_file: Option<&str>) -> Result<(), String> {
    if let Ok(exe) = std::env::current_exe() {
        let _ = DAEMON_EXE.set(exe);
    }

    config::initialize(config_file)?;

    logger::initialize();
    // Touch the metrics registry so bindizr_started_at_seconds reflects process start.
    bindizr_core::metrics::metrics();

    service::notify::init_notify_worker();

    database::initialize().await.map_err(|e| e.to_string())?;

    service::dnssec::init_maintenance_scheduler();

    let shutdown = Shutdown::new();
    dns::initialize(&shutdown).await?;

    if config::bindizr_config().dns.notify_on_startup {
        match service::notify::send_notify(None).await {
            Ok(()) => log_info!("Startup DNS NOTIFY completed."),
            Err(e) => log_error!("Startup DNS NOTIFY failed: {}", e),
        }
    }

    log_info!("Bindizr is running in foreground mode.");
    log_info!("For production use, please run bindizr as a systemd service:");
    log_info!("# systemctl start bindizr");

    let mut control_rx = socket::server::control::init();
    let socket_task = socket::server::initialize(&shutdown).await?;
    let api_task = api::initialize(&shutdown).await?;

    let mut terminate = signal(SignalKind::terminate())
        .map_err(|e| format!("Failed to listen for SIGTERM: {}", e))?;

    loop {
        let control = tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|e| format!("Failed to listen for shutdown signal: {}", e))?;
                log_info!("Interrupt received, shutting down...");
                break;
            }
            _ = terminate.recv() => {
                log_info!("SIGTERM received, shutting down...");
                break;
            }
            control = control_rx.recv() => control,
        };

        match control {
            Some(socket::server::control::DaemonControl::Restart) => {
                log_info!("Restart requested, re-executing bindizr...");
                // reexec only returns on failure; the listeners are still
                // serving, so keep running instead of turning it into an outage.
                log_error!("{}. Continuing with the current process.", reexec());
            }
            _ => {
                log_info!("Shutdown requested, exiting gracefully...");
                break;
            }
        }
    }

    shutdown.trigger();

    // In-flight zone transfers are not waited on: a cut transfer is one the
    // secondary discards and retries.
    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
        let _ = tokio::join!(socket_task, api_task);
    })
    .await;
    if drained.is_err() {
        log_error!(
            "Servers did not finish within {:?}, exiting anyway.",
            DRAIN_TIMEOUT
        );
    }

    Ok(())
}

/// Re-exec the original command line in place. exec keeps the PID, so
/// systemd/docker supervision and a foreground terminal stay attached.
/// Returns only when exec itself fails.
fn reexec() -> String {
    use std::os::unix::process::CommandExt;

    let Some(exe) = DAEMON_EXE.get() else {
        return "Failed to locate the bindizr executable".to_string();
    };
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();

    let err = std::process::Command::new(exe).args(args).exec();
    format!("Failed to re-execute bindizr: {}", err)
}
