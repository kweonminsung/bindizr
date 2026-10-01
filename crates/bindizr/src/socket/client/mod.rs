use bindizr_service::types::ErrorResponse;
use serde::de::DeserializeOwned;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use crate::{
    cli::error::CliError,
    socket::{
        FALLBACK_SOCKET_FILE_PATH, SOCKET_FILE_PATH, is_trusted_peer, read_own_uid,
        types::{DaemonCommand, DaemonResponse},
    },
};

/// True only when nothing listens on either socket path; a timeout or
/// garbled response may come from a live but wedged daemon.
pub(crate) async fn is_daemon_socket_gone() -> bool {
    /// Check whether a connection error means no daemon is listening.
    fn gone(err: &std::io::Error) -> bool {
        matches!(
            err.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        )
    }

    match try_connect_daemon_socket().await {
        Ok(_) => false,
        // An owner-only socket this user cannot open is a live daemon.
        Err(ConnectDaemonSocketError { primary: err, .. })
            if err.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            false
        }
        // Primary refused/missing; the fallback was also tried.
        Err(ConnectDaemonSocketError {
            fallback: Some(fallback_err),
            ..
        }) => gone(&fallback_err),
        // Primary failed in an unexpected way; the fallback was not tried.
        Err(ConnectDaemonSocketError {
            primary: err,
            fallback: None,
        }) => gone(&err),
    }
}

/// Send a command the daemon answers from memory (status/lifecycle) under
/// a short deadline, so a wedged daemon cannot hang polling loops.
pub(crate) async fn send_control_command<T: DeserializeOwned>(
    command: DaemonCommand,
) -> Result<DaemonResponse<T>, CliError> {
    const CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    tokio::time::timeout(CONTROL_TIMEOUT, send_command(command))
        .await
        .map_err(|e| {
            CliError::request_with_source(
                format!(
                    "the daemon did not answer within {} seconds",
                    CONTROL_TIMEOUT.as_secs()
                ),
                e,
            )
        })?
}

/// Send a command to the daemon and read its response, whose payload is
/// the `T` the command answers with.
pub(crate) async fn send_command<T: DeserializeOwned>(
    command: DaemonCommand,
) -> Result<DaemonResponse<T>, CliError> {
    let mut stream = connect_to_daemon_socket().await?;

    let json = serde_json::to_string(&command).map_err(|e| {
        CliError::request_with_source(format!("failed to serialize command: {}", e), e)
    })?;

    stream.write_all(json.as_bytes()).await.map_err(|e| {
        CliError::request_with_source(format!("failed to write to socket: {}", e), e)
    })?;
    stream.write_all(b"\n").await.map_err(|e| {
        CliError::request_with_source(format!("failed to write newline to socket: {}", e), e)
    })?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();

    reader.read_line(&mut response).await.map_err(|e| {
        CliError::request_with_source(format!("failed to read from socket: {}", e), e)
    })?;

    // An error reply is an `ErrorResponse` instead of a `DaemonResponse`,
    // so only a failed command parses here.
    if let Ok(error) = serde_json::from_str::<ErrorResponse>(&response) {
        return Err(CliError::from_daemon(Some(error.code), error.error));
    }

    serde_json::from_str(&response)
        .map_err(|e| CliError::request_with_source(format!("failed to parse response: {}", e), e))
}
/// Open a connection to the daemon's control socket, refusing a daemon that
/// is neither this user's nor root's (a socket another user planted in /tmp).
async fn connect_to_daemon_socket() -> Result<UnixStream, CliError> {
    let stream = try_connect_daemon_socket()
        .await
        .map_err(|error| {
            let denied_path = if error.primary.kind() == std::io::ErrorKind::PermissionDenied {
                Some(SOCKET_FILE_PATH)
            } else if error.fallback.as_ref().is_some_and(|fallback| fallback.kind() == std::io::ErrorKind::PermissionDenied) {
                Some(FALLBACK_SOCKET_FILE_PATH)
            } else {
                None
            };
            match denied_path {
                Some(path) => CliError::request_with_source(format!(
                    "permission denied on the daemon socket at '{}'. Run the CLI as the daemon's user (for a package install, `sudo bindizr ...`).", path
                ), error),
                None => CliError::daemon_unreachable(error),
            }
        })?;

    let peer_uid = stream
        .peer_cred()
        .map_err(|e| {
            CliError::request_with_source(
                format!("could not identify the daemon behind its socket: {}", e),
                e,
            )
        })?
        .uid();
    let own_uid = read_own_uid().map_err(|e| {
        CliError::request_with_source(format!("could not read this process's uid: {}", e), e)
    })?;
    // Root drives any daemon, as `sudo bindizr` on a package install does.
    if own_uid != 0 && !is_trusted_peer(peer_uid, own_uid) {
        let path = stream
            .peer_addr()
            .ok()
            .and_then(|addr| addr.as_pathname().map(|p| p.display().to_string()))
            .unwrap_or_else(|| "?".to_string());
        return Err(CliError::request(format!(
            "the daemon at '{}' runs as uid {}, neither this user nor root. Run the CLI as that \
             user, or remove a socket another user left there.",
            path, peer_uid
        )));
    }
    Ok(stream)
}

/// Io-level connect attempt, preserving the error(s) so callers can tell a
/// vanished socket apart from other failures.
async fn try_connect_daemon_socket() -> Result<UnixStream, ConnectDaemonSocketError> {
    match UnixStream::connect(SOCKET_FILE_PATH).await {
        Ok(stream) => Ok(stream),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
            ) =>
        {
            match UnixStream::connect(FALLBACK_SOCKET_FILE_PATH).await {
                Ok(stream) => Ok(stream),
                Err(fallback_err) => Err(ConnectDaemonSocketError {
                    primary: err,
                    fallback: Some(fallback_err),
                }),
            }
        }
        Err(err) => Err(ConnectDaemonSocketError {
            primary: err,
            fallback: None,
        }),
    }
}

/// Failed connection attempts to the primary and optional fallback socket.
#[derive(Debug, thiserror::Error)]
#[error(
    "could not connect to the daemon socket at '{SOCKET_FILE_PATH}': {primary}{}; is the bindizr daemon running?",
    fallback.as_ref().map(|error| format!("; fallback '{FALLBACK_SOCKET_FILE_PATH}': {error}")).unwrap_or_default()
)]
struct ConnectDaemonSocketError {
    #[source]
    primary: std::io::Error,
    fallback: Option<std::io::Error>,
}
