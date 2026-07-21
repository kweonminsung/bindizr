mod notify;
mod record;
mod status;
mod token;
mod zone;

use std::{io, os::unix::fs::FileTypeExt, path::Path};

use bindizr_core::{log_error, log_info, log_warn};
use bindizr_service::error::ServiceError;
use serde_json::json;
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

use crate::socket::{
    FALLBACK_SOCKET_FILE_PATH, SOCKET_FILE_PATH,
    types::{DaemonCommand, DaemonCommandKind},
};

/// Upper bound on a single command line, so a buggy or malicious client cannot
/// force unbounded allocation. Sized above the HTTP upload cap (32 MB) because
/// zone-file content arrives JSON-escaped, roughly doubling in the worst case.
const MAX_COMMAND_LINE_BYTES: u64 = 64 * 1024 * 1024;

async fn handle_client(stream: UnixStream) {
    let mut reader = BufReader::new(stream).take(MAX_COMMAND_LINE_BYTES);
    let mut line = String::new();

    if reader.read_line(&mut line).await.is_ok() {
        let parsed: Result<DaemonCommand, _> = serde_json::from_str(&line);

        let raw_response = match parsed {
            Ok(cmd) => match cmd.command {
                DaemonCommandKind::Status => status::get_status(),
                DaemonCommandKind::TokenCreate => token::create_token(&cmd.data).await,
                DaemonCommandKind::TokenList => token::list_tokens().await,
                DaemonCommandKind::TokenDelete => token::delete_token(&cmd.data).await,
                DaemonCommandKind::GetZone => zone::get_zone(&cmd.data).await,
                DaemonCommandKind::ListZones => zone::list_zones(&cmd.data).await,
                DaemonCommandKind::CreateZone => zone::create_zone(&cmd.data).await,
                DaemonCommandKind::DeleteZone => zone::delete_zone(&cmd.data).await,
                DaemonCommandKind::GetRecord => record::get_record(&cmd.data).await,
                DaemonCommandKind::ListRecords => record::list_records(&cmd.data).await,
                DaemonCommandKind::CreateRecord => record::create_record(&cmd.data).await,
                DaemonCommandKind::BulkCreateRecords => {
                    record::bulk_create_records(&cmd.data).await
                }
                DaemonCommandKind::DeleteRecord => record::delete_record(&cmd.data).await,
                DaemonCommandKind::NotifyZone => notify::handle_notify_zone(cmd.data).await,
                DaemonCommandKind::ImportZoneFile => zone::import_zone(&cmd.data).await,
                DaemonCommandKind::ListZoneSnapshots => zone::list_zone_snapshots(&cmd.data).await,
                DaemonCommandKind::GetZoneSnapshot => zone::get_zone_snapshot(&cmd.data).await,
                DaemonCommandKind::RollbackZone => zone::rollback_zone(&cmd.data).await,
            },

            Err(e) => {
                log_error!("Failed to parse command: {}", e);
                Err(ServiceError::invalid_input("Failed to parse command"))
            }
        };

        let response = match raw_response {
            Ok(res) => serde_json::to_string(&res).unwrap_or_else(|_| {
                json_response_error(&ServiceError::internal("Failed to serialize response"))
            }),
            Err(e) => json_response_error(&e),
        };

        let mut stream = reader.into_inner().into_inner();
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(b"\n").await;
    }
}

/// Bind the daemon's Unix socket and spawn the connection accept loop.
pub(crate) async fn initialize() -> Result<(), String> {
    let (socket_path, listener) = bind_daemon_socket().await?;

    log_info!("Daemon socket server listening on {}", socket_path);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        handle_client(stream).await;
                    });
                }
                Err(e) => {
                    log_error!("Error accepting connection: {}", e);
                }
            }
        }
    });

    Ok(())
}

/// Socket paths tried in order when the daemon starts.
const SOCKET_PATH_CANDIDATES: [&str; 2] = [SOCKET_FILE_PATH, FALLBACK_SOCKET_FILE_PATH];

async fn bind_daemon_socket() -> Result<(String, UnixListener), String> {
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
            log_warn!(
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

async fn bind_socket(socket_path: &str) -> io::Result<UnixListener> {
    prepare_socket_path(socket_path).await?;
    UnixListener::bind(socket_path)
}

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

fn json_response_error(err: &ServiceError) -> String {
    json!({
        "error": err.message,
        "code": err.code.as_str(),
    })
    .to_string()
}

#[cfg(test)]
mod tests;
