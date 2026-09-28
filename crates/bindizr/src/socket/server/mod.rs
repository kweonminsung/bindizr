//! Unix-socket daemon API for the CLI. Every command runs with global access
//! (no token scoping), so a connection is admitted only from the daemon's own
//! user or root, by the peer credentials the kernel reports.

pub(crate) mod control;
mod dnssec;
mod dnssec_policy;
mod doctor;
mod notify;
mod record;
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
};

/// Upper bound on a single command line, so a buggy or malicious client cannot
/// force unbounded allocation. Sized above the HTTP upload cap (32 MB) because
/// zone-file content arrives JSON-escaped, roughly doubling in the worst case.
const MAX_COMMAND_LINE_BYTES: u64 = 64 * 1024 * 1024;

/// Why the control socket could not be bound.
#[derive(Debug, Error)]
pub(crate) enum BindSocketError {
    /// Another daemon answers on the socket; its message is the io error's.
    #[error("{0}")]
    InUse(#[source] io::Error),
    /// Every candidate path failed, each with its reason.
    #[error("Failed to bind the daemon Unix socket ({})", failures.iter().map(|(path, e)| format!("'{path}': {e}")).collect::<Vec<_>>().join("; "))]
    Unavailable { failures: Vec<(String, io::Error)> },
}

/// Why the bound socket could not be served.
#[derive(Debug, Error)]
pub(crate) enum ServeSocketError {
    #[error("Failed to read the daemon's uid: {0}")]
    ReadUid(#[source] io::Error),
}

/// The socket front end's context: the daemon's, plus the control channel
/// the lifecycle loop awaits. A command handler takes the daemon's context;
/// only a control command needs this one.
#[derive(Debug)]
pub(crate) struct SocketContext {
    daemon: Arc<Context>,
    control: mpsc::Sender<DaemonControl>,
}

impl SocketContext {
    /// The front end's context over the daemon's.
    pub(crate) fn new(daemon: Arc<Context>, control: mpsc::Sender<DaemonControl>) -> Self {
        SocketContext { daemon, control }
    }

    /// The daemon's context.
    pub(crate) fn daemon(&self) -> &Context {
        &self.daemon
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
                    "Failed to parse command: {}",
                    e
                )))
            }
        };

        let mut stream = reader.into_inner().into_inner();
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(b"\n").await;
    }
}

/// Serve control commands on an already-bound socket until `shutdown` fires,
/// admitting only the daemon's own user and root.
///
/// The daemon removes the socket file once everything has drained: `bindizr
/// stop` waits for it to disappear, so removing it earlier would report a stop
/// that is still in progress.
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
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                return Err(BindSocketError::InUse(err));
            }
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
async fn bind_socket(socket_path: &str) -> io::Result<UnixListener> {
    prepare_socket_path(socket_path).await?;
    let listener = UnixListener::bind(socket_path)?;
    // Owner-only refuses strangers at connect; the peer check in `serve` is the boundary.
    fs::set_permissions(socket_path, Permissions::from_mode(0o600)).await?;
    Ok(listener)
}

/// Prepare the control socket path and remove a stale socket if needed.
async fn prepare_socket_path(socket_path: &str) -> io::Result<()> {
    if let Some(parent) = Path::new(socket_path).parent() {
        fs::create_dir_all(parent).await?;
    }

    match fs::symlink_metadata(socket_path).await {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "socket path exists and is not a Unix socket: {}",
                        socket_path
                    ),
                ));
            }

            match UnixStream::connect(socket_path).await {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Bindizr is already running.",
                )),
                // Socket file exists but no process is listening, so it is safe to remove.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(socket_path).await
                }
                // Socket disappeared after metadata lookup, so there is nothing to remove.
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Run one command and encode its answer as the line the client reads.
async fn handle_command(socket_cx: &SocketContext, command: DaemonCommand) -> String {
    let cx = socket_cx.daemon();
    match command {
        DaemonCommand::Status => encode_response(status::handle_status(cx).await),
        DaemonCommand::Config => encode_response(Ok(status::config(cx))),
        DaemonCommand::ReloadConfig => encode_response(status::reload_config(cx)),
        DaemonCommand::Doctor => encode_response(doctor::check_installation(cx).await),
        DaemonCommand::Shutdown => encode_response(Ok(control::shutdown(socket_cx))),
        DaemonCommand::Restart => encode_response(Ok(control::restart(socket_cx))),
        DaemonCommand::CreateToken(request) => {
            encode_response(token::create_token(cx, &request).await)
        }
        DaemonCommand::ListTokens(page) => encode_response(token::list_tokens(cx, page).await),
        DaemonCommand::DeleteToken { name } => {
            encode_response(token::delete_token(cx, &name).await)
        }
        DaemonCommand::CreateTokenGrant {
            token_name,
            request,
        } => encode_response(token::create_token_grant(cx, &token_name, &request).await),
        DaemonCommand::ListTokenGrants { token_name, page } => {
            encode_response(token::list_token_grants(cx, &token_name, page).await)
        }
        DaemonCommand::ListZoneTokenGrants { zone_name, page } => {
            encode_response(token::list_zone_token_grants(cx, &zone_name, page).await)
        }
        DaemonCommand::DeleteTokenGrant { id } => {
            encode_response(token::delete_token_grant(cx, id).await)
        }
        DaemonCommand::DeleteTokenGrantsByTokenAndZone {
            token_name,
            zone_name,
        } => encode_response(
            token::delete_token_grants_by_token_and_zone(cx, &token_name, &zone_name).await,
        ),
        DaemonCommand::CreateTsigKey(request) => {
            encode_response(tsig_key::create_tsig_key(cx, &request).await)
        }
        DaemonCommand::ListTsigKeys(page) => {
            encode_response(tsig_key::list_tsig_keys(cx, page).await)
        }
        DaemonCommand::GetTsigKey { name } => {
            encode_response(tsig_key::get_tsig_key(cx, &name).await)
        }
        DaemonCommand::DeleteTsigKey { name } => {
            encode_response(tsig_key::delete_tsig_key(cx, &name).await)
        }
        DaemonCommand::CreateTsigGrant { key_name, request } => {
            encode_response(tsig_key::create_tsig_grant(cx, &key_name, &request).await)
        }
        DaemonCommand::ListTsigGrants { key_name, page } => {
            encode_response(tsig_key::list_tsig_grants(cx, &key_name, page).await)
        }
        DaemonCommand::ListZoneTsigGrants { zone_name, page } => {
            encode_response(tsig_key::list_zone_tsig_grants(cx, &zone_name, page).await)
        }
        DaemonCommand::DeleteTsigGrant { id } => {
            encode_response(tsig_key::delete_tsig_grant(cx, id).await)
        }
        DaemonCommand::DeleteTsigGrantsByKeyAndZone {
            key_name,
            zone_name,
        } => encode_response(
            tsig_key::delete_tsig_grants_by_key_and_zone(cx, &key_name, &zone_name).await,
        ),
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
            scope,
        } => encode_response(zone::list_zone_versions(cx, &name, limit, offset, scope).await),
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
        DaemonCommand::DeleteRecordsMatching(filter) => {
            encode_response(record::delete_records_matching(cx, &filter).await)
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
        DaemonCommand::AdvanceDnssecRollover {
            zone_name,
            ds_check,
            holddown,
        } => encode_response(
            dnssec::advance_dnssec_rollover(cx, &zone_name, ds_check, holddown).await,
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
        Ok(response) => serde_json::to_string(&response).unwrap_or_else(|_| {
            encode_error(&ServiceError::internal("Failed to serialize response"))
        }),
        Err(e) => encode_error(&e),
    }
}

/// Encode a service error as one JSON line.
fn encode_error(err: &ServiceError) -> String {
    serde_json::to_string(&ErrorResponse::new(err)).unwrap_or_else(|_| {
        r#"{"error":"Failed to serialize error response","code":"INTERNAL"}"#.to_string()
    })
}

#[cfg(test)]
mod tests;
