mod notify;
mod record;
mod status;
mod token;
mod zone;

use std::{io, os::unix::fs::FileTypeExt, path::Path};

use bindizr_core::{log_error, log_info, log_warn};
use serde_json::json;
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

use crate::socket::{
    socket::{FALLBACK_SOCKET_FILE_PATH, SOCKET_FILE_PATH},
    types::{DaemonCommand, DaemonCommandKind},
};

async fn handle_client(stream: UnixStream) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    if reader.read_line(&mut line).await.is_ok() {
        let parsed: Result<DaemonCommand, _> = serde_json::from_str(&line);

        let raw_response = match parsed {
            Ok(cmd) => match cmd.command {
                // General commands
                DaemonCommandKind::Status => status::get_status(),
                DaemonCommandKind::TokenCreate => token::create_token(&cmd.data).await,
                DaemonCommandKind::TokenList => token::list_tokens().await,
                DaemonCommandKind::TokenDelete => token::delete_token(&cmd.data).await,
                // Zone commands
                DaemonCommandKind::GetZone => zone::get_zone(&cmd.data).await,
                DaemonCommandKind::ListZones => zone::list_zones(&cmd.data).await,
                DaemonCommandKind::CreateZone => zone::create_zone(&cmd.data).await,
                DaemonCommandKind::DeleteZone => zone::delete_zone(&cmd.data).await,
                // Record commands
                DaemonCommandKind::GetRecord => record::get_record(&cmd.data).await,
                DaemonCommandKind::ListRecords => record::list_records(&cmd.data).await,
                DaemonCommandKind::CreateRecord => record::create_record(&cmd.data).await,
                DaemonCommandKind::DeleteRecord => record::delete_record(&cmd.data).await,
                // Notify commands
                DaemonCommandKind::NotifyZone => notify::handle_notify_zone(cmd.data).await,
            },

            Err(e) => {
                log_error!("Failed to parse command: {}", e);
                Err("Failed to parse command".to_string())
            }
        };

        let response = match raw_response {
            Ok(res) => serde_json::to_string(&res)
                .unwrap_or_else(|_| json_response_error("Failed to serialize response")),
            Err(e) => json_response_error(&e),
        };

        let mut stream = reader.into_inner();
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(b"\n").await;
    }
}

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

async fn bind_daemon_socket() -> Result<(String, UnixListener), String> {
    match bind_socket(SOCKET_FILE_PATH).await {
        Ok(listener) => Ok((SOCKET_FILE_PATH.to_string(), listener)),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            log_warn!(
                "Cannot use default Unix socket path '{}': {}. Falling back to '{}'.",
                SOCKET_FILE_PATH,
                err,
                FALLBACK_SOCKET_FILE_PATH
            );

            bind_socket(FALLBACK_SOCKET_FILE_PATH)
                .await
                .map(|listener| (FALLBACK_SOCKET_FILE_PATH.to_string(), listener))
                .map_err(|err| {
                    format!(
                        "Failed to use fallback Unix socket path '{}': {}",
                        FALLBACK_SOCKET_FILE_PATH, err
                    )
                })
        }
        Err(err) => Err(format!(
            "Failed to use Unix socket path '{}': {}",
            SOCKET_FILE_PATH, err
        )),
    }
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

fn json_response_error(msg: &str) -> String {
    json!({
        "error": msg
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prepare_socket_path_creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("run").join("bindizr.sock");
        let socket_path = socket_path.to_str().unwrap();

        prepare_socket_path(socket_path).await.unwrap();

        assert!(Path::new(socket_path).parent().unwrap().exists());
    }

    #[tokio::test]
    async fn prepare_socket_path_removes_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("bindizr.sock");
        let socket_path = socket_path.to_str().unwrap();
        let listener = match UnixListener::bind(socket_path) {
            Ok(listener) => listener,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("failed to bind test socket: {}", e),
        };
        drop(listener);

        prepare_socket_path(socket_path).await.unwrap();

        assert!(!std::path::Path::new(socket_path).exists());
    }

    #[tokio::test]
    async fn prepare_socket_path_rejects_active_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("bindizr.sock");
        let socket_path = socket_path.to_str().unwrap();
        let listener = match UnixListener::bind(socket_path) {
            Ok(listener) => listener,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("failed to bind test socket: {}", e),
        };

        let err = prepare_socket_path(socket_path).await.unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        assert!(std::path::Path::new(socket_path).exists());
        drop(listener);
    }

    #[tokio::test]
    async fn prepare_socket_path_rejects_non_socket_file() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("bindizr.sock");
        let socket_path = socket_path.to_str().unwrap();
        std::fs::write(socket_path, "not a socket").unwrap();

        let err = prepare_socket_path(socket_path).await.unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(std::path::Path::new(socket_path).exists());
    }
}
