//! Build daemon dependencies, serve until shutdown and re-exec on restart; the CLI starts it.

pub(crate) mod db_probe;

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, io};

use bindizr_core::config::{Config, ConfigError};
use bindizr_core::logger::Logger;
use bindizr_core::metrics::{Metrics, RegisterMetricsError};
use bindizr_core::{config, logger};
use bindizr_db::Db;
use bindizr_db::error::DatabaseError;
use bindizr_service::access::AccessLogWorker;
use bindizr_service::context::ReloadConfigError;
use bindizr_service::error::{ErrorCode, ServiceError};
use bindizr_service::notify::queue;
use bindizr_service::notify::queue::NotifyWorker;
use bindizr_service::scheduler::SchedulerWorker;
use bindizr_service::{Context, access, scheduler, token, zone};
use chrono::Utc;
use thiserror::Error;
use tokio::net::UnixListener;
use tokio::signal::unix::{self, Signal, SignalKind};
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::{sync, time};

use crate::api::StartApiError;
use crate::dns::StartDnsError;
use crate::dns::error::DnsError;
use crate::dns::server::transfer_cache::TransferCache;
use crate::shutdown::Shutdown;
use crate::socket::server;
use crate::socket::server::control::DaemonControl;
use crate::socket::server::{BindSocketError, ServeSocketError, SocketContext, control};
use crate::tls::{LoadCertificateError, TlsCertificates};
use crate::{api, dns};

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
    #[error("shutdown or reload signal {signal} failed: {source}")]
    Signal {
        signal: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("the {name} stopped")]
    ServerStopped { name: &'static str },
    #[error("the {name} failed: {source}")]
    ServerFailed {
        name: &'static str,
        #[source]
        source: ServeError,
    },
    #[error("the {name} task failed: {source}")]
    ServerTaskFailed {
        name: &'static str,
        #[source]
        source: JoinError,
    },
    #[error("a server supervisor task failed: {0}")]
    SupervisorFailed(#[source] JoinError),
    #[error("failed to locate the bindizr executable")]
    ExecutableUnknown,
    #[error("failed to re-execute bindizr: {0}")]
    Reexec(#[source] io::Error),
}

impl DaemonError {
    /// Return whether running the same thing again would fail the same way: the
    /// exit class a supervisor stops retrying on.
    pub(crate) fn is_configuration(&self) -> bool {
        // A catalog name that clashes with a stored zone stays clashing until
        // the configuration changes; a database fault from that check does not.
        match self {
            Self::Config(_) | Self::Tls(_) => true,
            Self::CatalogZone(error) => error.code() == ErrorCode::ZoneConflict,
            _ => false,
        }
    }
}

/// Why a bound front end failed while serving.
#[derive(Debug, Error)]
pub(crate) enum ServeError {
    #[error("{0}")]
    Http(#[from] io::Error),
    #[error("{0}")]
    Dns(#[from] DnsError),
}

/// Supervised front-end tasks paired with their names; `join_next` removes
/// finished tasks so shutdown never awaits a handle twice.
type Servers = JoinSet<(&'static str, Result<Result<(), ServeError>, JoinError>)>;

/// Put a spawned front end under the daemon's supervision.
fn watch<T: Send + 'static>(
    servers: &mut Servers,
    name: &'static str,
    task: JoinHandle<T>,
    serve_result: impl FnOnce(T) -> Result<(), ServeError> + Send + 'static,
) {
    servers.spawn(async move { (name, task.await.map(serve_result)) });
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
    fn from(error: ReloadError) -> Self {
        match error {
            ReloadError::Config(error) => Self::from(error),
            tls @ ReloadError::Tls(_) => Self::invalid_input_with_source(tls.to_string(), tls),
        }
    }
}

/// Apply live settings from either SIGHUP or the control socket.
#[derive(Debug)]
pub(crate) struct ConfigReloader {
    tls: TlsCertificates,
    transfer_cache: Arc<TransferCache>,
    reload: Mutex<()>,
}

impl ConfigReloader {
    /// Share the listener state affected by each reload.
    pub(crate) fn new(tls: TlsCertificates, transfer_cache: Arc<TransferCache>) -> Self {
        Self {
            tls,
            transfer_cache,
            reload: Mutex::new(()),
        }
    }

    /// Serialize reloads so the daemon and listeners finish each update together.
    pub(crate) fn reload(&self, cx: &Context) -> Result<Vec<String>, ReloadError> {
        let _reload = self.reload.lock().expect("Bindizr reload lock is poisoned");
        // The file and both certificate pairs are read before anything is replaced.
        let next = cx.load_config()?;
        let certificates = self.tls.reload(&next)?;
        let mut changed = cx.set_config(next);

        let config = cx.config();
        logger::set_level(config.logging.level);
        logger::set_format(config.logging.format);
        self.transfer_cache.reconcile_budget(cx);

        // A new period also reaches a scheduler that was idle at zero.
        cx.set_scheduler_period(config.dns.scheduler_interval_secs);

        changed.extend(certificates);
        log::info!("event=config_reload changed={}", changed.join(","));

        Ok(changed)
    }
}

/// Build the daemon's state in dependency order, serve every front end, handle
/// reload/restart/shutdown requests, and drain on shutdown.
pub(crate) async fn bootstrap(config_file: Option<&str>) -> Result<(), DaemonError> {
    // Captured at startup: after a package upgrade /proc/self/exe reads as a
    // "(deleted)" path, while this path points at the replacement.
    let daemon_exe = env::current_exe().ok();

    let config_path = config::resolve_config_path(config_file)?;
    let config = Config::load(&config_path)?;

    Logger::init(config.logging);

    // Reported after the logger exists, so it carries the configured format.
    log::info!("Configuration loaded from {config_path}");

    // Bind the control socket first so a second daemon fails before
    // opening the database or claiming DNS ports.
    let (socket_file, socket_listener) = server::bind().await?;
    log::info!("Daemon socket server listening on {}", socket_file.path());

    let outcome = run(config, config_path, socket_listener).await;
    server::remove_socket_file(socket_file).await;

    match outcome? {
        RunResult::Stop => Ok(()),
        // exec replaces this image, so it returns only on failure, and by
        // then nothing is listening: the failure ends the process.
        RunResult::Restart => Err(reexec(daemon_exe)),
    }
}

/// Prepare the daemon and drain anything started before returning its outcome.
async fn run(
    config: Config,
    config_path: String,
    socket_listener: Arc<UnixListener>,
) -> Result<RunResult, DaemonError> {
    let mut interrupt = listen_for_signal("SIGINT", SignalKind::interrupt())?;
    let mut terminate = listen_for_signal("SIGTERM", SignalKind::terminate())?;
    let mut hangup = listen_for_signal("SIGHUP", SignalKind::hangup())?;
    // Read before the database opens: a pair that does not load is a
    // configuration failure.
    let tls = TlsCertificates::load(&config)?;

    let db = Db::connect(&config.database).await?;

    // The channels come before the context, which holds their senders; the
    // workers come after it, since they need the context back.
    let (notify_tx, notify_rx) = sync::mpsc::unbounded_channel();
    let (access_tx, access_rx) = access::channel();
    let (period_tx, period_rx) = sync::watch::channel(config.dns.scheduler_interval_secs);
    let authentication_required = config.api.authentication_required;
    let cx = Arc::new(Context::new(
        config,
        config_path,
        db,
        Metrics::new()?,
        notify_tx,
        access_tx,
        period_tx,
    ));
    zone::validate_catalog_zone_name(&cx).await?;

    // Authentication with no token answers 401 to everything, which reads as a
    // broken deployment rather than one nobody has been let into yet.
    if authentication_required {
        match token::count_all(&cx).await {
            Ok(0) => log::warn!(
                "API authentication is on and no API tokens exist; create one with `bindizr token create admin --role admin`"
            ),
            Ok(_) => {}
            Err(error) => log::warn!("Could not count API tokens: {error}"),
        }
    }

    let notify_worker = queue::spawn(cx.clone(), notify_rx);
    let access_log_worker = access::spawn(cx.clone(), access_rx);
    let scheduler_worker = scheduler::spawn(cx.clone(), period_rx);
    let shutdown = Shutdown::new();
    let mut servers = Servers::new();

    let outcome = async {
        let dns_servers = dns::start(cx.clone(), &shutdown, tls.dns.clone()).await?;
        watch(&mut servers, "DNS TCP server", dns_servers.tcp, |result| {
            result.map_err(ServeError::from)
        });
        watch(&mut servers, "DNS UDP server", dns_servers.udp, Ok);
        if let Some(task) = dns_servers.tls {
            watch(&mut servers, "DNS TLS server", task, |result| {
                result.map_err(ServeError::from)
            });
        }

        let (control_tx, mut control_rx) = control::channel();
        let reloader = Arc::new(ConfigReloader::new(tls.clone(), dns_servers.transfer_cache));
        let socket_cx = Arc::new(SocketContext::new(cx.clone(), control_tx, reloader.clone()));
        let socket_task = server::serve(socket_cx, socket_listener, &shutdown)?;
        watch(&mut servers, "daemon socket server", socket_task, Ok);

        let api_task = api::start(cx.clone(), &shutdown, tls.api.clone()).await?;
        watch(&mut servers, "API server", api_task, |result| {
            result.map_err(ServeError::from)
        });

        // Publish the start time only after all front ends serve; restart
        // polling and the uptime gauge use this same readiness point.
        cx.set_started_at(Utc::now());
        log::info!("Bindizr is running.");

        loop {
            let control = tokio::select! {
                result = recv_signal("SIGINT", &mut interrupt) => {
                    result?;
                    log::info!("Interrupt received, shutting down...");
                    break Ok(RunResult::Stop);
                }

                result = recv_signal("SIGTERM", &mut terminate) => {
                    result?;
                    log::info!("SIGTERM received, shutting down...");
                    break Ok(RunResult::Stop);
                }

                result = recv_signal("SIGHUP", &mut hangup) => {
                    result?;
                    if let Err(error) = reloader.reload(&cx) {
                        log::error!("SIGHUP received, nothing reloaded: {error}");
                    }

                    continue;
                }

                // A listener stopping independently makes the daemon unhealthy.
                Some(result) = servers.join_next() => {
                    let (name, result) = result.map_err(DaemonError::SupervisorFailed)?;
                    break Err(server_stopped(name, result));
                }

                control = control_rx.recv() => control,
            };

            match control {
                Some(DaemonControl::Restart) => {
                    log::info!("Restart requested, re-executing bindizr...");
                    break Ok(RunResult::Restart);
                }
                _ => {
                    log::info!("Shutdown requested, exiting gracefully...");
                    break Ok(RunResult::Stop);
                }
            }
        }
    }
    .await;

    drain(
        &shutdown,
        servers,
        scheduler_worker,
        notify_worker,
        access_log_worker,
    )
    .await;
    outcome
}

/// Why the lifecycle loop ended.
#[derive(Debug)]
enum RunResult {
    Stop,
    Restart,
}

/// Report an independently stopped server with its actual failure, if any.
fn server_stopped(
    name: &'static str,
    result: Result<Result<(), ServeError>, JoinError>,
) -> DaemonError {
    match result {
        Ok(Ok(())) => DaemonError::ServerStopped { name },
        Ok(Err(source)) => DaemonError::ServerFailed { name, source },
        Err(source) => DaemonError::ServerTaskFailed { name, source },
    }
}

/// Register an operating-system signal before listeners start serving.
fn listen_for_signal(signal: &'static str, kind: SignalKind) -> Result<Signal, DaemonError> {
    unix::signal(kind).map_err(|source| DaemonError::Signal { signal, source })
}

/// Wait for a signal, reporting a lost receiver as a supervisor failure.
async fn recv_signal(signal: &'static str, receiver: &mut Signal) -> Result<(), DaemonError> {
    receiver.recv().await.ok_or_else(|| DaemonError::Signal {
        signal,
        source: io::Error::new(io::ErrorKind::BrokenPipe, "signal listener closed"),
    })
}

/// Drain requests and scheduler work, then flush NOTIFY and the access log
/// within the shutdown timeout. Zone transfers may be interrupted for
/// secondaries to retry.
async fn drain(
    shutdown: &Shutdown,
    mut servers: Servers,
    scheduler_worker: SchedulerWorker,
    notify_worker: NotifyWorker,
    access_log_worker: AccessLogWorker,
) {
    shutdown.trigger();

    let drained = time::timeout(DRAIN_TIMEOUT, async {
        while let Some(result) = servers.join_next().await {
            match result {
                Ok((_, Ok(Ok(())))) => {}
                Ok((name, result)) => log::warn!("{}", server_stopped(name, result)),
                Err(error) => log::warn!("{}", DaemonError::SupervisorFailed(error)),
            }
        }

        // The scheduler is a write producer too; its last pass may enqueue NOTIFY.
        wait_for_worker("DNSSEC scheduler", scheduler_worker.stop()).await;

        // Flush only after every NOTIFY producer has stopped.
        wait_for_worker("NOTIFY worker", notify_worker.stop()).await;

        // The front ends were the access log's producers, and they have stopped.
        wait_for_worker("access log worker", access_log_worker.stop()).await;
    })
    .await;

    if drained.is_err() {
        log::error!("Servers did not finish within {DRAIN_TIMEOUT:?}, exiting anyway.");
    }
}

/// Join a stopping worker and retain the cause if it cannot drain.
async fn wait_for_worker(name: &str, task: JoinHandle<()>) {
    if let Err(error) = task.await {
        log::warn!("{name} did not stop cleanly: {error}");
    }
}

/// Re-exec the original command in place, preserving PID, supervision and terminal attachment.
/// Return only if exec fails.
fn reexec(daemon_exe: Option<PathBuf>) -> DaemonError {
    let Some(exe) = daemon_exe else {
        return DaemonError::ExecutableUnknown;
    };
    let args: Vec<OsString> = env::args_os().skip(1).collect();

    DaemonError::Reexec(Command::new(exe).args(args).exec())
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use bindizr_core::config::TlsFiles;
    use rustls::pki_types::pem;

    use super::*;
    use crate::tls::TlsCertificate;

    /// Verify that a TLS reload failure retains its read cause, error code, and message.
    #[test]
    fn tls_reload_failure_preserves_source_and_response() {
        let directory = tempfile::tempdir().unwrap();
        let cert_file = directory.path().join("missing-cert.pem");
        let key_file = directory.path().join("missing-key.pem");
        let source = TlsCertificate::load(TlsFiles {
            cert_file: cert_file.to_str().unwrap(),
            key_file: key_file.to_str().unwrap(),
        })
        .unwrap_err();
        let reload = ReloadError::from(source);
        let message = reload.to_string();

        let error = ServiceError::from(reload);

        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert_eq!(error.to_string(), message);
        let reload = error
            .source()
            .unwrap()
            .downcast_ref::<ReloadError>()
            .unwrap();
        let certificate = reload
            .source()
            .unwrap()
            .downcast_ref::<LoadCertificateError>()
            .unwrap();
        let read = certificate
            .source()
            .unwrap()
            .downcast_ref::<pem::Error>()
            .unwrap();
        assert!(matches!(read, pem::Error::Io(error) if error.kind() == io::ErrorKind::NotFound));
    }

    /// Verify that the supervisor can distinguish a stopped listener from its serving error.
    #[test]
    fn server_stopped_preserves_the_listener_error() {
        let failure = ServeError::from(io::Error::new(io::ErrorKind::BrokenPipe, "listener lost"));
        let error = server_stopped("API server", Ok(Err(failure)));
        let source = error
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
        assert!(matches!(
            server_stopped("API server", Ok(Ok(()))),
            DaemonError::ServerStopped { name: "API server" }
        ));
    }
}
