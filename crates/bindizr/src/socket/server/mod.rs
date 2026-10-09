//! Unix-socket daemon API for the CLI. Every command runs with global access
//! (no token scoping), so a connection is admitted only from the daemon's own
//! user or root, by the peer credentials the kernel reports.

pub(crate) mod control;
mod dnssec;
mod dnssec_policy;
mod doctor;
mod notify;
mod record;
mod role;
mod secondary;
pub(crate) mod status;
mod token;
mod tsig_key;
mod zone;

use std::{
    fs::Permissions,
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    sync::Arc,
};

use bindizr_service::{Context, error::ServiceError, types::ErrorResponse};
use control::DaemonControl;
use thiserror::Error;
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::mpsc,
    task::JoinHandle,
};

use crate::{
    shutdown::Shutdown,
    socket::{
        FALLBACK_SOCKET_FILE_PATH, SOCKET_FILE_PATH, is_trusted_peer, read_own_uid,
        types::{DaemonCommand, DaemonResponse},
    },
    tls::TlsCertificates,
};

/// Upper bound on a single command line, so a buggy or malicious client cannot
/// force unbounded allocation. Sized above the HTTP upload cap (32 MB) because
/// zone-file content arrives JSON-escaped, roughly doubling in the worst case.
const MAX_COMMAND_LINE_BYTES: u64 = 64 * 1024 * 1024;

/// Why the control socket could not be bound.
#[derive(Debug, Error)]
pub(crate) enum BindSocketError {
    /// Another daemon answers on the socket.
    #[error("Bindizr is already running")]
    InUse,
    /// Every candidate path failed, each with its reason.
    #[error("failed to bind the daemon Unix socket ({})", failures.iter().map(|(path, e)| format!("'{path}': {e}")).collect::<Vec<_>>().join("; "))]
    Unavailable {
        failures: Vec<(String, BindSocketPathError)>,
    },
}

/// Why one candidate path could not be bound.
#[derive(Debug, Error)]
pub(crate) enum BindSocketPathError {
    /// A daemon answers on the socket at this path.
    #[error("Bindizr is already running")]
    AlreadyRunning,
    /// Something other than a Unix socket sits at the path.
    #[error("socket path exists and is not a Unix socket: {path}")]
    NotASocket { path: String },
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Why the bound socket could not be served.
#[derive(Debug, Error)]
pub(crate) enum ServeSocketError {
    #[error("failed to read the daemon's uid: {0}")]
    ReadUid(#[source] io::Error),
}

/// The socket front end's context: the daemon's, plus the control channel
/// the lifecycle loop awaits. A command handler takes the daemon's context;
/// only a control command needs this one.
#[derive(Debug, Clone)]
pub(crate) struct SocketContext {
    daemon: Arc<Context>,
    control: mpsc::Sender<DaemonControl>,
    /// The certificates a reload re-reads.
    tls: TlsCertificates,
}

impl SocketContext {
    /// The front end's context over the daemon's.
    pub(crate) fn new(
        daemon: Arc<Context>,
        control: mpsc::Sender<DaemonControl>,
        tls: TlsCertificates,
    ) -> Self {
        SocketContext {
            daemon,
            control,
            tls,
        }
    }

    /// The daemon's context.
    pub(crate) fn daemon(&self) -> &Context {
        &self.daemon
    }

    /// The certificates the TLS listeners present.
    pub(crate) fn tls(&self) -> &TlsCertificates {
        &self.tls
    }

    /// The sender a shutdown or restart request goes down.
    pub(crate) fn control(&self) -> &mpsc::Sender<DaemonControl> {
        &self.control
    }
}

/// Dispatch a control request and send its JSON response.
async fn handle_client(socket_cx: &SocketContext, stream: UnixStream) {
    let mut reader = BufReader::new(stream).take(MAX_COMMAND_LINE_BYTES);
    let mut line = String::new();

    if reader.read_line(&mut line).await.is_ok() {
        // A connect-and-close is another `bindizr start` probing whether this
        // daemon is alive (`prepare_socket_path`), not a command.
        if line.is_empty() {
            return;
        }

        let response = match serde_json::from_str::<DaemonCommand>(&line) {
            Ok(command) => handle_command(socket_cx, command).await,
            Err(e) => {
                log::error!("Failed to parse command: {}", e);
                encode_error(&ServiceError::invalid_input(format!(
                    "failed to parse command: {}",
                    e
                )))
            }
        };

        let mut stream = reader.into_inner().into_inner();
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(b"\n").await;
    }
}

/// Serve control commands for the daemon's user and root until `shutdown` fires.
/// Remove the socket only after draining: `bindizr stop` uses its disappearance as completion.
pub(crate) fn serve(
    socket_cx: Arc<SocketContext>,
    listener: UnixListener,
    shutdown: &Shutdown,
) -> Result<JoinHandle<()>, ServeSocketError> {
    let own_uid = read_own_uid().map_err(ServeSocketError::ReadUid)?;
    let stop = shutdown.waiter();
    Ok(tokio::spawn(async move {
        tokio::pin!(stop);

        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                () = &mut stop => break,
            };

            match accepted {
                // Connecting grants global access, so the peer is checked before a byte is read.
                Ok((stream, _)) => match stream.peer_cred() {
                    Ok(peer) if is_trusted_peer(peer.uid(), own_uid) => {
                        let socket_cx = socket_cx.clone();
                        tokio::spawn(async move {
                            handle_client(&socket_cx, stream).await;
                        });
                    }
                    Ok(peer) => {
                        log::warn!("Refused a daemon socket connection from uid {}", peer.uid());
                    }
                    // Another `bindizr start` probing whether this daemon is alive
                    // has hung up already, and macOS keeps no credentials past that.
                    Err(e) if e.kind() == io::ErrorKind::NotConnected => {}
                    Err(e) => {
                        log::warn!(
                            "Refused a daemon socket connection with no peer credentials: {}",
                            e
                        );
                    }
                },
                Err(e) => {
                    log::error!("Error accepting connection: {}", e);
                }
            }
        }

        drop(listener);
        log::info!("Daemon socket server stopped");
    }))
}

/// Remove the daemon's socket file, once nothing is serving on it.
pub(crate) async fn remove_socket_file(socket_path: &str) {
    if let Err(e) = fs::remove_file(socket_path).await {
        log::warn!("Failed to remove the daemon socket {}: {}", socket_path, e);
    }
}

/// Socket paths tried in order when the daemon starts.
const SOCKET_PATH_CANDIDATES: [&str; 2] = [SOCKET_FILE_PATH, FALLBACK_SOCKET_FILE_PATH];

/// Bind the daemon's configured control socket. Owning it is what refuses a
/// second daemon, so the daemon binds before anything else it would share.
pub(crate) async fn bind() -> Result<(String, UnixListener), BindSocketError> {
    let mut failures = Vec::new();

    for (i, path) in SOCKET_PATH_CANDIDATES.iter().enumerate() {
        let err = match bind_socket(path).await {
            Ok(listener) => return Ok(((*path).to_string(), listener)),
            // Another daemon already owns this socket. Trying the next candidate
            // would start a second daemon instead of reporting the conflict.
            Err(BindSocketPathError::AlreadyRunning) => return Err(BindSocketError::InUse),
            Err(err) => err,
        };

        if let Some(next) = SOCKET_PATH_CANDIDATES.get(i + 1) {
            log::warn!(
                "Cannot use Unix socket path '{}': {}. Falling back to '{}'.",
                path,
                err,
                next
            );
        }
        failures.push((path.to_string(), err));
    }
    Err(BindSocketError::Unavailable { failures })
}

/// Bind a Unix listener at the requested path.
async fn bind_socket(socket_path: &str) -> Result<UnixListener, BindSocketPathError> {
    prepare_socket_path(socket_path).await?;
    // A daemon that bound this path after the check above answers EADDRINUSE
    // here: the same conflict, not a path to fall back from.
    let listener = UnixListener::bind(socket_path).map_err(|e| match e.kind() {
        io::ErrorKind::AddrInUse => BindSocketPathError::AlreadyRunning,
        _ => BindSocketPathError::Io(e),
    })?;
    // Owner-only refuses strangers at connect; the peer check in `serve` is the boundary.
    fs::set_permissions(socket_path, Permissions::from_mode(0o600)).await?;
    Ok(listener)
}

/// Prepare the control socket path and remove a stale socket if needed.
async fn prepare_socket_path(socket_path: &str) -> Result<(), BindSocketPathError> {
    if let Some(parent) = Path::new(socket_path).parent() {
        fs::create_dir_all(parent).await?;
    }

    match fs::symlink_metadata(socket_path).await {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(BindSocketPathError::NotASocket {
                    path: socket_path.to_string(),
                });
            }

            match UnixStream::connect(socket_path).await {
                Ok(_) => Err(BindSocketPathError::AlreadyRunning),
                // Socket file exists but no process is listening, so it is safe to remove.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    Ok(fs::remove_file(socket_path).await?)
                }
                // Socket disappeared after metadata lookup, so there is nothing to remove.
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Run one command and encode its answer as the line the client reads.
async fn handle_command(socket_cx: &SocketContext, command: DaemonCommand) -> String {
    let cx = socket_cx.daemon();
    match command {
        DaemonCommand::Status => encode_response(status::handle_status(cx).await),
        DaemonCommand::Config => encode_response(Ok(status::config(cx))),
        DaemonCommand::ReloadConfig => encode_response(status::reload_config(socket_cx)),
        DaemonCommand::Doctor => encode_response(doctor::check_installation(cx).await),
        DaemonCommand::Shutdown => encode_response(Ok(control::shutdown(socket_cx))),
        DaemonCommand::Restart => encode_response(Ok(control::restart(socket_cx))),
        DaemonCommand::CreateToken(request) => {
            encode_response(token::create_token(cx, &request).await)
        }
        DaemonCommand::ListTokens(filter) => encode_response(token::list_tokens(cx, &filter).await),
        DaemonCommand::DeleteToken { name } => {
            encode_response(token::delete_token(cx, &name).await)
        }
        DaemonCommand::CreateRole(request) => {
            encode_response(role::create_role(cx, &request).await)
        }
        DaemonCommand::ListRoles(page) => encode_response(role::list_roles(cx, page).await),
        DaemonCommand::GetRole { name } => encode_response(role::get_role(cx, &name).await),
        DaemonCommand::DeleteRole { name } => encode_response(role::delete_role(cx, &name).await),
        DaemonCommand::CreateRoleGrant { role_name, request } => {
            encode_response(role::create_role_grant(cx, &role_name, &request).await)
        }
        DaemonCommand::ListRoleGrants { role_name, page } => {
            encode_response(role::list_role_grants(cx, &role_name, page).await)
        }
        DaemonCommand::DeleteRoleGrant { role_name, id } => {
            encode_response(role::delete_role_grant(cx, &role_name, id).await)
        }
        DaemonCommand::CreateTsigKey(request) => {
            encode_response(tsig_key::create_tsig_key(cx, &request).await)
        }
        DaemonCommand::ListTsigKeys(filter) => {
            encode_response(tsig_key::list_tsig_keys(cx, &filter).await)
        }
        DaemonCommand::GetTsigKey { name } => {
            encode_response(tsig_key::get_tsig_key(cx, &name).await)
        }
        DaemonCommand::DeleteTsigKey { name } => {
            encode_response(tsig_key::delete_tsig_key(cx, &name).await)
        }
        DaemonCommand::CreateSecondary(request) => {
            encode_response(secondary::create_secondary(cx, &request).await)
        }
        DaemonCommand::ListSecondaries(page) => {
            encode_response(secondary::list_secondaries(cx, page).await)
        }
        DaemonCommand::GetSecondary { name } => {
            encode_response(secondary::get_secondary(cx, &name).await)
        }
        DaemonCommand::UpdateSecondary { name, request } => {
            encode_response(secondary::update_secondary(cx, &name, request).await)
        }
        DaemonCommand::DeleteSecondary { name } => {
            encode_response(secondary::delete_secondary(cx, &name).await)
        }
        DaemonCommand::CheckSecondary { name } => {
            encode_response(secondary::check_secondary(cx, &name).await)
        }
        DaemonCommand::ListSecondaryTransfers { name, filter } => {
            encode_response(secondary::list_secondary_transfers(cx, &name, filter).await)
        }
        DaemonCommand::CreateDnssecPolicy(request) => {
            encode_response(dnssec_policy::create_dnssec_policy(cx, request).await)
        }
        DaemonCommand::ListDnssecPolicies(page) => {
            encode_response(dnssec_policy::list_dnssec_policies(cx, page).await)
        }
        DaemonCommand::GetDnssecPolicy { name } => {
            encode_response(dnssec_policy::get_dnssec_policy(cx, &name).await)
        }
        DaemonCommand::UpdateDnssecPolicy { name, request } => {
            encode_response(dnssec_policy::update_dnssec_policy(cx, &name, request).await)
        }
        DaemonCommand::DeleteDnssecPolicy { name } => {
            encode_response(dnssec_policy::delete_dnssec_policy(cx, &name).await)
        }
        DaemonCommand::CreateZone(request) => {
            encode_response(zone::create_zone(cx, &request).await)
        }
        DaemonCommand::ListZones(filter) => encode_response(zone::list_zones(cx, filter).await),
        DaemonCommand::GetZone { name } => encode_response(zone::get_zone(cx, &name).await),
        DaemonCommand::UpdateZone { zone_name, request } => {
            encode_response(zone::update_zone(cx, &zone_name, &request).await)
        }
        DaemonCommand::DeleteZone { name, run } => {
            encode_response(zone::delete_zone(cx, &name, run).await)
        }
        DaemonCommand::ImportZone { zone_name, request } => {
            encode_response(zone::import_zone(cx, &zone_name, &request).await)
        }
        DaemonCommand::ExportZone { name, view } => {
            encode_response(zone::export_zone(cx, &name, view).await)
        }
        DaemonCommand::GetZoneStatus { name } => {
            encode_response(zone::get_zone_status(cx, &name).await)
        }
        DaemonCommand::NotifyZone { zone_name, serial } => {
            encode_response(notify::notify_zone(cx, &zone_name, serial).await)
        }
        DaemonCommand::NotifyAllZones { serial } => {
            encode_response(notify::notify_all_zones(cx, serial).await)
        }
        DaemonCommand::ListZoneVersions {
            name,
            limit,
            offset,
            filter,
        } => encode_response(zone::list_zone_versions(cx, &name, limit, offset, filter).await),
        DaemonCommand::GetZoneVersion { name, serial } => {
            encode_response(zone::get_zone_version(cx, &name, serial).await)
        }
        DaemonCommand::DiffZoneVersions {
            name,
            from_serial,
            to_serial,
        } => encode_response(zone::diff_zone_versions(cx, &name, from_serial, to_serial).await),
        DaemonCommand::RollbackZone { name, serial, run } => {
            encode_response(zone::rollback_zone(cx, &name, serial, run).await)
        }
        DaemonCommand::CreateRecord(request) => {
            encode_response(record::create_record(cx, &request).await)
        }
        DaemonCommand::CreateRecordsBulk(request) => {
            encode_response(record::create_records_bulk(cx, &request).await)
        }
        DaemonCommand::ListRecords(filter) => {
            encode_response(record::list_records(cx, filter).await)
        }
        DaemonCommand::GetRecord { id } => encode_response(record::get_record(cx, id).await),
        DaemonCommand::UpdateRecord { id, request } => {
            encode_response(record::update_record(cx, id, &request).await)
        }
        DaemonCommand::UpdateRecordByName {
            zone_name,
            record_name,
            request,
        } => encode_response(
            record::update_record_by_name(cx, &zone_name, &record_name, &request).await,
        ),
        DaemonCommand::DeleteRecord { id, run } => {
            encode_response(record::delete_record(cx, id, run).await)
        }
        DaemonCommand::DeleteRecordsMatching(request) => {
            encode_response(record::delete_records_matching(cx, &request).await)
        }
        DaemonCommand::EnableDnssec { zone_name, request } => {
            encode_response(dnssec::enable_dnssec(cx, &zone_name, &request).await)
        }
        DaemonCommand::DisableDnssec {
            zone_name,
            ds_check,
        } => encode_response(dnssec::disable_dnssec(cx, &zone_name, ds_check).await),
        DaemonCommand::GetDnssecStatus { name } => {
            encode_response(dnssec::get_dnssec_status(cx, &name).await)
        }
        DaemonCommand::SignZone { name } => encode_response(dnssec::sign_zone(cx, &name).await),
        DaemonCommand::StartDnssecRollover { zone_name, request } => {
            encode_response(dnssec::start_dnssec_rollover(cx, &zone_name, &request).await)
        }
        DaemonCommand::DsSeenDnssecRollover {
            zone_name,
            ds_check,
            holddown,
        } => encode_response(
            dnssec::ds_seen_dnssec_rollover(cx, &zone_name, ds_check, holddown).await,
        ),
        DaemonCommand::WithdrawDnssec { name } => {
            encode_response(dnssec::withdraw_dnssec(cx, &name).await)
        }
        DaemonCommand::CancelDnssecWithdrawal { name } => {
            encode_response(dnssec::cancel_dnssec_withdrawal(cx, &name).await)
        }
        DaemonCommand::UpdateDnssecSettings { zone_name, request } => {
            encode_response(dnssec::update_dnssec_settings(cx, &zone_name, &request).await)
        }
        DaemonCommand::CheckDnssecDs { name } => {
            encode_response(dnssec::check_dnssec_ds(cx, &name).await)
        }
        DaemonCommand::ExportDnssecKeys { name } => {
            encode_response(dnssec::export_dnssec_keys(cx, &name).await)
        }
        DaemonCommand::ImportDnssecKeys { zone_name, request } => {
            encode_response(dnssec::import_dnssec_keys(cx, &zone_name, request).await)
        }
    }
}

/// Encode a handler's response, or the error it failed with, as one JSON line.
fn encode_response<T: serde::Serialize>(result: Result<DaemonResponse<T>, ServiceError>) -> String {
    match result {
        Ok(response) => serde_json::to_string(&response).unwrap_or_else(|e| {
            encode_error(&ServiceError::internal_with_source(
                "failed to serialize response",
                e,
            ))
        }),
        Err(e) => encode_error(&e),
    }
}

/// Encode a service error as one JSON line.
fn encode_error(err: &ServiceError) -> String {
    serde_json::to_string(&ErrorResponse::from(err)).unwrap_or_else(|_| {
        r#"{"error":"failed to serialize error response","code":"INTERNAL"}"#.to_string()
    })
}

#[cfg(test)]
mod tests;
