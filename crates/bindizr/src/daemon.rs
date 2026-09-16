//! The daemon runtime: wiring the process together, serving until asked to
//! stop, and re-executing itself on restart. The CLI only decides when to
//! start it.

use std::time::Duration;

use bindizr_core::{config, logger};
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

/// Re-read the configuration file and apply what only a running process can:
/// the settings whose readers captured them at startup.
pub(crate) fn reload_config() -> Result<Vec<String>, String> {
    let changed = config::reload()?;
    // The installed logger reads its level and format per record, so this is enough.
    let config = config::bindizr_config();
    logger::set_level(config.logging.level);
    logger::set_format(config.logging.format);
    // A no-op unless this instance had no scheduler, which a zero interval
    // leaves it without.
    service::dnssec::init_maintenance_scheduler();
    Ok(changed)
}

/// Start daemon services, handle reload/restart/shutdown requests, and drain on shutdown.
pub(crate) async fn bootstrap(config_file: Option<&str>) -> Result<(), String> {
    if let Ok(exe) = std::env::current_exe() {
        let _ = DAEMON_EXE.set(exe);
    }

    // Prepare configuration and background services before accepting requests.
    config::initialize(config_file)?;

    logger::initialize();
    // Touch the metrics registry so bindizr_started_at_seconds reflects process start.
    bindizr_core::metrics::metrics();

    service::notify::init_notify_worker();

    database::initialize().await.map_err(|e| e.to_string())?;

    // A fresh install with authentication on answers 401 until a token exists.
    let config = config::bindizr_config();
    if let Some(key) = &config.dns.nsupdate.initial_key {
        match service::tsig_key::TsigKeyService::seed_initial(
            &key.name,
            key.algorithm.as_deref(),
            &key.secret,
        )
        .await
        {
            Ok(true) => log::info!(
                "Created the global TSIG key '{}' from dns.nsupdate.initial_key",
                key.name
            ),
            Ok(false) => {}
            Err(e) => return Err(format!("Failed to create the initial TSIG key: {}", e)),
        }
    }

    let authentication = &config.api.authentication;
    if let Some(secret) = &authentication.initial_token {
        match service::token::TokenService::seed_initial(secret).await {
            Ok(true) => log::info!(
                "Created the global API token 'initial' from api.authentication.initial_token"
            ),
            Ok(false) => {}
            Err(e) => return Err(format!("Failed to create the initial API token: {}", e)),
        }
    } else if authentication.required {
        match service::token::TokenService::count_all().await {
            Ok(0) => log::warn!(
                "API authentication is on and no API tokens exist; create one with `bindizr token create admin --global`"
            ),
            Ok(_) => {}
            Err(e) => log::warn!("Could not count API tokens: {}", e),
        }
    }

    service::dnssec::init_maintenance_scheduler();

    // DNS must be listening before startup NOTIFY can prompt secondary transfers.
    let shutdown = Shutdown::new();
    dns::initialize(&shutdown).await?;

    if config::bindizr_config().dns.notify.on_startup {
        match service::notify::send_notify(None).await {
            Ok(()) => log::info!("Startup DNS NOTIFY completed."),
            Err(e) => log::error!("Startup DNS NOTIFY failed: {}", e),
        }
    }

    log::info!("Bindizr is running.");

    let mut control_rx = socket::server::control::init();
    let socket_task = socket::server::initialize(&shutdown).await?;
    let api_task = api::initialize(&shutdown).await?;

    let mut terminate = signal(SignalKind::terminate())
        .map_err(|e| format!("Failed to listen for SIGTERM: {}", e))?;
    let mut hangup =
        signal(SignalKind::hangup()).map_err(|e| format!("Failed to listen for SIGHUP: {}", e))?;

    // Handle process signals and socket control commands in one lifecycle loop.
    loop {
        let control = tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|e| format!("Failed to listen for shutdown signal: {}", e))?;
                log::info!("Interrupt received, shutting down...");
                break;
            }
            _ = terminate.recv() => {
                log::info!("SIGTERM received, shutting down...");
                break;
            }
            _ = hangup.recv() => {
                match reload_config() {
                    Ok(changed) if changed.is_empty() => {
                        log::info!("SIGHUP received, nothing changed.")
                    }
                    Ok(changed) => {
                        log::info!("SIGHUP received, reloaded: {}", changed.join(", "))
                    }
                    Err(e) => log::error!("SIGHUP received, nothing reloaded: {}", e),
                }
                continue;
            }
            control = control_rx.recv() => control,
        };

        match control {
            Some(socket::server::control::DaemonControl::Restart) => {
                log::info!("Restart requested, re-executing bindizr...");
                // reexec only returns on failure; the listeners are still
                // serving, so keep running instead of turning it into an outage.
                log::error!("{}. Continuing with the current process.", reexec());
            }
            _ => {
                log::info!("Shutdown requested, exiting gracefully...");
                break;
            }
        }
    }

    // Stop accepting work before waiting for API and socket requests to finish.
    shutdown.trigger();

    // In-flight zone transfers are not waited on: a cut transfer is one the
    // secondary discards and retries.
    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
        let _ = tokio::join!(socket_task, api_task);
    })
    .await;
    if drained.is_err() {
        log::error!(
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
