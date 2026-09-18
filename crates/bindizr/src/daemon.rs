//! The daemon runtime: wiring the process together, serving until asked to
//! stop, and re-executing itself on restart. The CLI only decides when to
//! start it.

use std::time::Duration;

use bindizr_core::{config, logger};
use bindizr_db as database;
use bindizr_service as service;
use tokio::signal::unix::{SignalKind, signal};

use crate::{api, cli::error::CliError, dns, shutdown::Shutdown, socket};

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
    service::dnssec::initialize_scheduler();
    Ok(changed)
}

/// Start daemon services, handle reload/restart/shutdown requests, and drain on shutdown.
pub(crate) async fn bootstrap(config_file: Option<&str>) -> Result<(), CliError> {
    if let Ok(exe) = std::env::current_exe() {
        let _ = DAEMON_EXE.set(exe);
    }

    // Prepare configuration and background services before accepting requests.
    config::initialize(config_file).map_err(CliError::configuration)?;

    logger::initialize();
    // Touch the metrics registry so bindizr_started_at_seconds reflects process start.
    bindizr_core::metrics::metrics();

    // Binding this first is what refuses a second daemon: otherwise the loser
    // reports the conflict as a taken DNS port, after opening the database and
    // running the seeding.
    let (socket_path, socket_listener) = socket::server::bind().await?;
    log::info!("Daemon socket server listening on {}", socket_path);

    let notify_task = service::notify::initialize_worker();

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
            Err(e) => {
                return Err(CliError::from(format!(
                    "Failed to create the initial TSIG key: {}",
                    e
                )));
            }
        }
    }

    let authentication = &config.api.authentication;
    if let Some(secret) = &authentication.initial_token {
        match service::token::TokenService::seed_initial(secret).await {
            Ok(true) => log::info!(
                "Created the global API token 'initial' from api.authentication.initial_token"
            ),
            Ok(false) => {}
            Err(e) => {
                return Err(CliError::from(format!(
                    "Failed to create the initial API token: {}",
                    e
                )));
            }
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

    service::dnssec::initialize_scheduler();

    // DNS must be listening before startup NOTIFY can prompt secondary transfers.
    let shutdown = Shutdown::new();
    let (mut dns_tcp_task, mut dns_udp_task) = dns::initialize(&shutdown).await?;

    if config::bindizr_config().dns.notify.on_startup {
        match service::notify::send_notify(None).await {
            Ok(()) => log::info!("Startup DNS NOTIFY completed."),
            Err(e) => log::error!("Startup DNS NOTIFY failed: {}", e),
        }
    }

    let mut control_rx = socket::server::control::initialize();
    let mut socket_task = socket::server::serve(socket_listener, &shutdown);
    let mut api_task = api::initialize(&shutdown).await?;

    // Every front end is serving now, so the start time is what `bindizr
    // restart` waits for before it reports the daemon back up.
    socket::server::status::mark_start_time();
    log::info!("Bindizr is running.");

    let mut terminate = signal(SignalKind::terminate())
        .map_err(|e| format!("Failed to listen for SIGTERM: {}", e))?;
    let mut hangup =
        signal(SignalKind::hangup()).map_err(|e| format!("Failed to listen for SIGHUP: {}", e))?;

    // Handle process signals and socket control commands in one lifecycle loop.
    // A front end that stops on its own ends the daemon: the control socket
    // would otherwise keep answering for a process serving nothing.
    let outcome = loop {
        let control = tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|e| format!("Failed to listen for shutdown signal: {}", e))?;
                log::info!("Interrupt received, shutting down...");
                break Outcome::Stop;
            }
            _ = terminate.recv() => {
                log::info!("SIGTERM received, shutting down...");
                break Outcome::Stop;
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
            result = &mut socket_task => break Outcome::server_stopped("daemon socket server", result),
            result = &mut api_task => break Outcome::server_stopped("API server", result),
            result = &mut dns_tcp_task => break Outcome::server_stopped("DNS TCP server", result),
            result = &mut dns_udp_task => break Outcome::server_stopped("DNS UDP server", result),
            control = control_rx.recv() => control,
        };

        match control {
            Some(socket::server::control::DaemonControl::Restart) => {
                log::info!("Restart requested, re-executing bindizr...");
                break Outcome::Restart;
            }
            _ => {
                log::info!("Shutdown requested, exiting gracefully...");
                break Outcome::Stop;
            }
        }
    };

    drain(&shutdown, socket_task, api_task, notify_task).await;
    socket::server::remove_socket_file(&socket_path).await;

    match outcome {
        Outcome::Stop => Ok(()),
        Outcome::Failed(e) => Err(CliError::from(e)),
        // exec replaces this image, so it returns only on failure, and by
        // then nothing is listening: the failure ends the process.
        Outcome::Restart => Err(CliError::from(reexec())),
    }
}

/// Why the lifecycle loop ended.
enum Outcome {
    Stop,
    Restart,
    Failed(String),
}

impl Outcome {
    /// The outcome of a server that stopped on its own, so the exit says what
    /// failed.
    fn server_stopped(name: &str, result: Result<(), tokio::task::JoinError>) -> Self {
        Outcome::Failed(match result {
            Ok(()) => format!("The {} stopped", name),
            Err(e) => format!("The {} failed: {}", name, e),
        })
    }
}

/// Stop accepting work, then give in-flight requests and queued NOTIFYs a
/// bounded time to finish.
///
/// In-flight zone transfers are not waited on: a cut transfer is one the
/// secondary discards and retries.
async fn drain(
    shutdown: &Shutdown,
    socket_task: tokio::task::JoinHandle<()>,
    api_task: tokio::task::JoinHandle<()>,
    notify_task: Option<tokio::task::JoinHandle<()>>,
) {
    shutdown.trigger();
    service::notify::stop_worker();

    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
        let _ = tokio::join!(socket_task, api_task);
        if let Some(notify_task) = notify_task {
            let _ = notify_task.await;
        }
    })
    .await;
    if drained.is_err() {
        log::error!(
            "Servers did not finish within {:?}, exiting anyway.",
            DRAIN_TIMEOUT
        );
    }
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
