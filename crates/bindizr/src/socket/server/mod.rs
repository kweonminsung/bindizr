//! Unix-socket daemon API for the CLI; reachable only by the local daemon
//! owner, so every command runs with global access (no token scoping).

pub(crate) mod control;
mod dnssec;
mod dnssec_policy;
mod doctor;
mod notify;
mod record;
pub(crate) mod status;
mod token;
mod tsig_key;
mod zone;

use std::{
    fs::Permissions,
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
};

use bindizr_service::{error::ServiceError, types::ErrorResponse};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};

use crate::{
    shutdown::Shutdown,
    socket::{
        FALLBACK_SOCKET_FILE_PATH, SOCKET_FILE_PATH,
        types::{DaemonCommand, DaemonCommandKind},
    },
};

/// Upper bound on a single command line, so a buggy or malicious client cannot
/// force unbounded allocation. Sized above the HTTP upload cap (32 MB) because
/// zone-file content arrives JSON-escaped, roughly doubling in the worst case.
const MAX_COMMAND_LINE_BYTES: u64 = 64 * 1024 * 1024;

/// Dispatch a control request and send its JSON response.
async fn handle_client(stream: UnixStream) {
    let mut reader = BufReader::new(stream).take(MAX_COMMAND_LINE_BYTES);
    let mut line = String::new();

    if reader.read_line(&mut line).await.is_ok() {
        // A connect-and-close is another `bindizr start` probing whether this
        // daemon is alive (`prepare_socket_path`), not a command.
        if line.is_empty() {
            return;
        }

        let parsed: Result<DaemonCommand, _> = serde_json::from_str(&line);

        let raw_response = match parsed {
            Ok(cmd) => match cmd.command {
                DaemonCommandKind::Status => status::handle_status().await,
                DaemonCommandKind::Config => status::config(),
                DaemonCommandKind::ReloadConfig => status::reload_config(),
                DaemonCommandKind::CreateToken => token::create_token(&cmd.data).await,
                DaemonCommandKind::ListTokens => token::list_tokens(&cmd.data).await,
                DaemonCommandKind::DeleteToken => token::delete_token(&cmd.data).await,
                DaemonCommandKind::CreateTsigKey => tsig_key::create_tsig_key(&cmd.data).await,
                DaemonCommandKind::ListTsigKeys => tsig_key::list_tsig_keys(&cmd.data).await,
                DaemonCommandKind::GetTsigKey => tsig_key::get_tsig_key(&cmd.data).await,
                DaemonCommandKind::DeleteTsigKey => tsig_key::delete_tsig_key(&cmd.data).await,
                DaemonCommandKind::CreateDnssecPolicy => {
                    dnssec_policy::create_dnssec_policy(&cmd.data).await
                }
                DaemonCommandKind::ListDnssecPolicies => {
                    dnssec_policy::list_dnssec_policies(&cmd.data).await
                }
                DaemonCommandKind::GetDnssecPolicy => {
                    dnssec_policy::get_dnssec_policy(&cmd.data).await
                }
                DaemonCommandKind::UpdateDnssecPolicy => {
                    dnssec_policy::update_dnssec_policy(&cmd.data).await
                }
                DaemonCommandKind::DeleteDnssecPolicy => {
                    dnssec_policy::delete_dnssec_policy(&cmd.data).await
                }
                DaemonCommandKind::CreateTsigGrant => tsig_key::create_tsig_grant(&cmd.data).await,
                DaemonCommandKind::ListTsigGrants => tsig_key::list_tsig_grants(&cmd.data).await,
                DaemonCommandKind::ListZoneTsigGrants => {
                    tsig_key::list_zone_tsig_grants(&cmd.data).await
                }
                DaemonCommandKind::DeleteTsigGrant => tsig_key::delete_tsig_grant(&cmd.data).await,
                DaemonCommandKind::DeleteTsigGrantsByKeyAndZone => {
                    tsig_key::delete_tsig_grants_by_key_and_zone(&cmd.data).await
                }
                DaemonCommandKind::CreateTokenGrant => token::create_token_grant(&cmd.data).await,
                DaemonCommandKind::ListTokenGrants => token::list_token_grants(&cmd.data).await,
                DaemonCommandKind::ListZoneTokenGrants => {
                    token::list_zone_token_grants(&cmd.data).await
                }
                DaemonCommandKind::DeleteTokenGrant => token::delete_token_grant(&cmd.data).await,
                DaemonCommandKind::DeleteTokenGrantsByTokenAndZone => {
                    token::delete_token_grants_by_token_and_zone(&cmd.data).await
                }
                DaemonCommandKind::GetZone => zone::get_zone(&cmd.data).await,
                DaemonCommandKind::ListZones => zone::list_zones(&cmd.data).await,
                DaemonCommandKind::CreateZone => zone::create_zone(&cmd.data).await,
                DaemonCommandKind::UpdateZone => zone::update_zone(&cmd.data).await,
                DaemonCommandKind::DeleteZone => zone::delete_zone(&cmd.data).await,
                DaemonCommandKind::GetRecord => record::get_record(&cmd.data).await,
                DaemonCommandKind::ListRecords => record::list_records(&cmd.data).await,
                DaemonCommandKind::CreateRecord => record::create_record(&cmd.data).await,
                DaemonCommandKind::UpdateRecord => record::update_record(&cmd.data).await,
                DaemonCommandKind::UpdateRecordByName => {
                    record::update_record_by_name(&cmd.data).await
                }
                DaemonCommandKind::CreateRecordsBulk => {
                    record::create_records_bulk(&cmd.data).await
                }
                DaemonCommandKind::DeleteRecord => record::delete_record(&cmd.data).await,
                DaemonCommandKind::DeleteRecordsMatching => {
                    record::delete_records_matching(&cmd.data).await
                }
                DaemonCommandKind::NotifyAllZones => notify::notify_all_zones(&cmd.data).await,
                DaemonCommandKind::NotifyZone => notify::notify_zone(&cmd.data).await,
                DaemonCommandKind::ImportZone => zone::import_zone(&cmd.data).await,
                DaemonCommandKind::ExportZone => zone::export_zone(&cmd.data).await,
                DaemonCommandKind::ListZoneVersions => zone::list_zone_versions(&cmd.data).await,
                DaemonCommandKind::GetZoneVersion => zone::get_zone_version(&cmd.data).await,
                DaemonCommandKind::DiffZoneVersions => zone::diff_zone_versions(&cmd.data).await,
                DaemonCommandKind::RollbackZone => zone::rollback_zone(&cmd.data).await,
                DaemonCommandKind::GetZoneStatus => zone::get_zone_status(&cmd.data).await,
                DaemonCommandKind::EnableDnssec => dnssec::enable_dnssec(&cmd.data).await,
                DaemonCommandKind::DisableDnssec => dnssec::disable_dnssec(&cmd.data).await,
                DaemonCommandKind::GetDnssecStatus => dnssec::get_dnssec_status(&cmd.data).await,
                DaemonCommandKind::SignZone => dnssec::sign_zone(&cmd.data).await,
                DaemonCommandKind::StartDnssecRollover => {
                    dnssec::start_dnssec_rollover(&cmd.data).await
                }
                DaemonCommandKind::WithdrawDnssec => dnssec::withdraw_dnssec(&cmd.data).await,
                DaemonCommandKind::CancelDnssecWithdrawal => {
                    dnssec::cancel_dnssec_withdrawal(&cmd.data).await
                }
                DaemonCommandKind::UpdateDnssecSettings => {
                    dnssec::update_dnssec_settings(&cmd.data).await
                }
                DaemonCommandKind::CheckDnssecDs => dnssec::check_dnssec_ds(&cmd.data).await,
                DaemonCommandKind::ExportDnssecKeys => dnssec::export_dnssec_keys(&cmd.data).await,
                DaemonCommandKind::ImportDnssecKeys => dnssec::import_dnssec_keys(&cmd.data).await,
                DaemonCommandKind::DsSeenDnssecRollover => {
                    dnssec::ds_seen_dnssec_rollover(&cmd.data).await
                }
                DaemonCommandKind::Doctor => doctor::check_installation().await,
                DaemonCommandKind::Shutdown => control::shutdown(),
                DaemonCommandKind::Restart => control::restart(),
            },

            Err(e) => {
                log::error!("Failed to parse command: {}", e);
                Err(ServiceError::invalid_input("Failed to parse command"))
            }
        };

        let response = match raw_response {
            Ok(res) => serde_json::to_string(&res).unwrap_or_else(|_| {
                error_response_json(&ServiceError::internal("Failed to serialize response"))
            }),
            Err(e) => error_response_json(&e),
        };

        let mut stream = reader.into_inner().into_inner();
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(b"\n").await;
    }
}

/// Serve control commands on an already-bound socket until `shutdown` fires.
///
/// The daemon removes the socket file once everything has drained: `bindizr
/// stop` waits for it to disappear, so removing it earlier would report a stop
/// that is still in progress.
pub(crate) fn serve(listener: UnixListener, shutdown: &Shutdown) -> JoinHandle<()> {
    let stop = shutdown.waiter();
    tokio::spawn(async move {
        tokio::pin!(stop);

        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                () = &mut stop => break,
            };

            match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        handle_client(stream).await;
                    });
                }
                Err(e) => {
                    log::error!("Error accepting connection: {}", e);
                }
            }
        }

        drop(listener);
        log::info!("Daemon socket server stopped");
    })
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
pub(crate) async fn bind() -> Result<(String, UnixListener), String> {
    let mut failures = Vec::new();

    for (i, path) in SOCKET_PATH_CANDIDATES.iter().enumerate() {
        let err = match bind_socket(path).await {
            Ok(listener) => return Ok(((*path).to_string(), listener)),
            // Another daemon already owns this socket. Trying the next candidate
            // would start a second daemon instead of reporting the conflict.
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => return Err(err.to_string()),
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
        failures.push(format!("'{}': {}", path, err));
    }

    Err(format!(
        "Failed to bind the daemon Unix socket ({})",
        failures.join("; ")
    ))
}

/// Bind a Unix listener at the requested path.
async fn bind_socket(socket_path: &str) -> io::Result<UnixListener> {
    prepare_socket_path(socket_path).await?;
    let listener = UnixListener::bind(socket_path)?;
    // Connecting grants global access; the file mode is the auth boundary.
    fs::set_permissions(socket_path, Permissions::from_mode(0o600)).await?;
    Ok(listener)
}

/// Prepare the control socket path and remove a stale socket if needed.
async fn prepare_socket_path(socket_path: &str) -> io::Result<()> {
    if let Some(parent) = Path::new(socket_path).parent() {
        fs::create_dir_all(parent).await?;
        // 0700 before the socket exists: the directory gates access, so the
        // bind-then-chmod window cannot leak a umask-permissive socket.
        fs::set_permissions(parent, Permissions::from_mode(0o700)).await?;
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

/// Deserialize a command payload into its typed parameter struct, so missing
/// and wrongly typed fields are rejected instead of silently defaulting.
pub(crate) fn parse_params<T: serde::de::DeserializeOwned>(
    data: &serde_json::Value,
) -> Result<T, ServiceError> {
    serde_json::from_value(data.clone())
        .map_err(|e| ServiceError::invalid_input(format!("Invalid command payload: {}", e)))
}

/// Serialize a handler result into the `DaemonResponse` data payload.
pub(crate) fn to_response_data<T: serde::Serialize>(
    value: T,
) -> Result<serde_json::Value, ServiceError> {
    serde_json::to_value(value)
        .map_err(|e| ServiceError::internal(format!("Failed to serialize response: {}", e)))
}

/// Serialize a service error as a control response.
fn error_response_json(err: &ServiceError) -> String {
    serde_json::to_string(&ErrorResponse::new(err)).unwrap_or_else(|_| {
        r#"{"error":"Failed to serialize error response","code":"INTERNAL"}"#.to_string()
    })
}

#[cfg(test)]
mod tests;
