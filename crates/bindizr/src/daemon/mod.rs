//! The daemon runtime: building the `Context` in dependency order, serving
//! until asked to stop, and re-executing itself on restart. The CLI only
//! decides when to start it.

pub(crate) mod db_probe;

use std::{path::PathBuf, sync::Arc, time::Duration};

use bindizr_core::{
    config::{self, Config, ConfigError},
    logger::{self, Logger},
    metrics::{Metrics, RegisterMetricsError},
};
use bindizr_db::{Db, error::DatabaseError};
use bindizr_service::{
    Context, context::ReloadConfigError, dnssec::scheduler, error::ServiceError, notify::queue,
    token, zone,
};
use chrono::Utc;
use thiserror::Error;
use tokio::{
    signal::unix::{SignalKind, signal},
    task::{JoinError, JoinHandle, JoinSet},
};

use crate::{
    api,
    api::StartApiError,
    dns,
    dns::StartDnsError,
    shutdown::Shutdown,
    socket,
    socket::server::{BindSocketError, ServeSocketError},
    tls::{LoadCertificateError, TlsCertificates},
};

/// How long the servers that can finish on their own get before the daemon
/// exits anyway.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the daemon did not start, or why it stopped.
#[derive(Debug, Error)]
pub(crate) enum DaemonError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A pair that cannot be read is permanent, so it exits as a
    /// configuration failure rather than looping through systemd's restart.
    #[error(transparent)]
    Tls(#[from] LoadCertificateError),
    #[error(transparent)]
    Socket(#[from] BindSocketError),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    Metrics(#[from] RegisterMetricsError),
    /// The catalog zone name is a stored zone's; the service names the clash.
    #[error(transparent)]
    CatalogZone(#[from] ServiceError),
    #[error(transparent)]
    Dns(#[from] StartDnsError),
    #[error(transparent)]
    ServeSocket(#[from] ServeSocketError),
    #[error(transparent)]
    Api(#[from] StartApiError),
    #[error("failed to listen for {signal}: {source}")]
    Signal {
        signal: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("the {name} stopped")]
    ServerStopped { name: &'static str },
    #[error("the {name} failed: {source}")]
    ServerFailed {
        name: &'static str,
        #[source]
        source: tokio::task::JoinError,
    },
    #[error("failed to locate the bindizr executable")]
    ExecutableUnknown,
    #[error("failed to re-execute bindizr: {0}")]
    Reexec(#[source] std::io::Error),
}

impl DaemonError {
    /// Whether running the same thing again would fail the same way: the
    /// exit class a supervisor stops retrying on.
    pub(crate) fn is_configuration(&self) -> bool {
        matches!(self, DaemonError::Config(_) | DaemonError::Tls(_))
    }
}

/// Supervised front-end tasks paired with their names; `join_next` removes
/// finished tasks so shutdown never awaits a handle twice.
type Servers = JoinSet<(&'static str, Result<(), JoinError>)>;

/// Put a spawned front end under the daemon's supervision.
fn watch(servers: &mut Servers, name: &'static str, task: JoinHandle<()>) {
    servers.spawn(async move { (name, task.await) });
}

/// Why a reload applied nothing, or not everything.
#[derive(Debug, Error)]
pub(crate) enum ReloadError {
    #[error(transparent)]
    Config(#[from] ReloadConfigError),
    #[error("nothing was reloaded: {0}")]
    Tls(#[from] LoadCertificateError),
}

/// A refused reload is the operator's to fix: a pair that does not load is
/// invalid input, as a refused configuration is.
impl From<ReloadError> for ServiceError {
    /// Classify the reload failure for the error payload.
    fn from(err: ReloadError) -> Self {
        match err {
            ReloadError::Config(err) => ServiceError::from(err),
            tls @ ReloadError::Tls(_) => ServiceError::invalid_input(tls),
        }
    }
}

/// Re-read the configuration file and apply what only a running process can:
/// the settings whose readers captured them at startup, and the certificate
/// pairs the TLS listeners present.
pub(crate) fn reload_config(
    cx: &Context,
    tls: &TlsCertificates,
) -> Result<Vec<String>, ReloadError> {
    // Everything that can fail, the file and both certificate pairs, is read
    // before anything is replaced, so a refusal leaves the daemon as it was.
    let next = cx.load_config()?;
    let certificates = tls.reload(&next)?;
    let mut changed = cx.set_config(next);

    // The installed logger reads its level and format per record, so this is enough.
    let config = cx.config();
    logger::set_level(config.logging.level);
    logger::set_format(config.logging.format);

    // The scheduler takes its period from the channel, so a reload that
    // names one reaches an instance a zero interval left idle.
    cx.set_scheduler_period(config.dns.scheduler_interval_secs);

    changed.extend(certificates);
    Ok(changed)
}

/// Build the daemon's state in dependency order, serve every front end, handle
/// reload/restart/shutdown requests, and drain on shutdown.
pub(crate) async fn bootstrap(config_file: Option<&str>) -> Result<(), DaemonError> {
    // Captured at startup: after a package upgrade /proc/self/exe reads as a
    // "(deleted)" path, while this path points at the replacement.
    let daemon_exe = std::env::current_exe().ok();

    let config_path = config::resolve_config_path(config_file);
    let config = Config::load(&config_path)?;

    Logger::init(&config.logging);
    // Reported after the logger exists, so it carries the configured format.
    log::info!("Configuration loaded from {}", config_path);

    // Bind the control socket first so a second daemon fails before
    // opening the database or claiming DNS ports.
    let (socket_path, socket_listener) = socket::server::bind().await?;
    log::info!("Daemon socket server listening on {}", socket_path);

    // Read before the database opens: a pair that does not load is a
    // configuration failure.
    let tls = TlsCertificates::load(&config)?;

    let db = Db::connect(&config.database).await?;

    // The channels come before the context, which holds their senders; the
    // workers come after it, since they need the context back.
    let (notify_tx, notify_rx) = queue::channel();
    let (period_tx, period_rx) = scheduler::channel(config.dns.scheduler_interval_secs);
    let authentication_required = config.api.authentication_required;
    let cx = Arc::new(Context::new(
        config,
        config_path,
        db,
        Metrics::new()?,
        notify_tx,
        period_tx,
    ));
    let notify_worker = queue::spawn(cx.clone(), notify_rx);

    zone::validate_catalog_zone_name(&cx).await?;

    // Authentication with no token answers 401 to everything, which reads as a
    // broken deployment rather than one nobody has been let into yet.
    if authentication_required {
        match token::count_all(&cx).await {
            Ok(0) => log::warn!(
                "API authentication is on and no API tokens exist; create one with `bindizr token create admin --role admin`"
            ),
            Ok(_) => {}
            Err(e) => log::warn!("Could not count API tokens: {}", e),
        }
    }

    scheduler::spawn(cx.clone(), period_rx);

    let shutdown = Shutdown::new();
    let dns_servers = dns::initialize(cx.clone(), &shutdown, tls.dns.clone()).await?;

    let (control_tx, mut control_rx) = socket::server::control::channel();
    let socket_cx = Arc::new(socket::server::SocketContext::new(
        cx.clone(),
        control_tx,
        tls.clone(),
    ));
    let socket_task = socket::server::serve(socket_cx, socket_listener, &shutdown)?;
    let api_task = api::initialize(cx.clone(), &shutdown, tls.api.clone()).await?;

    // A front end that stops on its own ends the daemon: the control socket
    // would otherwise keep answering for a process serving nothing.
    let mut servers = Servers::new();
    watch(&mut servers, "daemon socket server", socket_task);
    watch(&mut servers, "API server", api_task);
    watch(&mut servers, "DNS TCP server", dns_servers.tcp);
    watch(&mut servers, "DNS UDP server", dns_servers.udp);
    if let Some(task) = dns_servers.tls {
        watch(&mut servers, "DNS TLS server", task);
    }

    // Publish the start time only after all front ends serve; restart
    // polling and the uptime gauge use this same readiness point.
    cx.set_started_at(Utc::now());
    log::info!("Bindizr is running.");

    let mut terminate = signal(SignalKind::terminate()).map_err(|source| DaemonError::Signal {
        signal: "SIGTERM",
        source,
    })?;
    let mut hangup = signal(SignalKind::hangup()).map_err(|source| DaemonError::Signal {
        signal: "SIGHUP",
        source,
    })?;

    // Handle process signals and socket control commands in one lifecycle loop.
    let outcome = loop {
        let control = tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|source| DaemonError::Signal {
                    signal: "shutdown signal",
                    source,
                })?;
                log::info!("Interrupt received, shutting down...");
                break RunResult::Stop;
            }
            _ = terminate.recv() => {
                log::info!("SIGTERM received, shutting down...");
                break RunResult::Stop;
            }
            _ = hangup.recv() => {
                match reload_config(&cx, &tls) {
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
            Some(Ok((name, result))) = servers.join_next() => {
                break RunResult::server_stopped(name, result);
            }
            control = control_rx.recv() => control,
        };

        match control {
            Some(socket::server::control::DaemonControl::Restart) => {
                log::info!("Restart requested, re-executing bindizr...");
                break RunResult::Restart;
            }
            _ => {
                log::info!("Shutdown requested, exiting gracefully...");
                break RunResult::Stop;
            }
        }
    };

    drain(&shutdown, servers, notify_worker).await;
    socket::server::remove_socket_file(&socket_path).await;

    match outcome {
        RunResult::Stop => Ok(()),
        RunResult::Failed(e) => Err(e),
        // exec replaces this image, so it returns only on failure, and by
        // then nothing is listening: the failure ends the process.
        RunResult::Restart => Err(reexec(daemon_exe)),
    }
}

/// Why the lifecycle loop ended.
#[derive(Debug)]
enum RunResult {
    Stop,
    Restart,
    Failed(DaemonError),
}

impl RunResult {
    /// The result of a server that stopped on its own, so the exit says what
    /// failed.
    fn server_stopped(name: &'static str, result: Result<(), tokio::task::JoinError>) -> Self {
        RunResult::Failed(match result {
            Ok(()) => DaemonError::ServerStopped { name },
            Err(source) => DaemonError::ServerFailed { name, source },
        })
    }
}

/// Stop accepting work and drain requests and queued NOTIFYs within the shutdown timeout.
/// Detached zone transfers are not awaited; secondaries discard and retry interrupted transfers.
async fn drain(shutdown: &Shutdown, mut servers: Servers, notify_worker: queue::NotifyWorker) {
    shutdown.trigger();

    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while servers.join_next().await.is_some() {}

        // The worker outlives the front ends: an in-flight write still enqueues.
        // Not a front end: its exit never ends the daemon.
        let _ = notify_worker.stop().await;
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
fn reexec(daemon_exe: Option<PathBuf>) -> DaemonError {
    use std::os::unix::process::CommandExt;

    let Some(exe) = daemon_exe else {
        return DaemonError::ExecutableUnknown;
    };
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();

    DaemonError::Reexec(std::process::Command::new(exe).args(args).exec())
}
