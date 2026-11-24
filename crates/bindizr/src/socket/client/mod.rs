use std::fs::Metadata;
use std::future::Future;
use std::io;
use std::time::Duration;

use bindizr_service::types::{ErrorResponse, MessageResponse};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::{fs, time};

use crate::cli::error::CliError;
use crate::socket;
use crate::socket::types::{DaemonCommand, DaemonResponse};
use crate::socket::{FALLBACK_SOCKET_FILE_PATH, SOCKET_FILE_PATH, SocketFileId, SocketPathError};

/// Why one daemon socket candidate could not be connected.
#[derive(Debug, Error)]
enum ConnectSocketPathError {
    #[error("unsafe daemon socket directory '{path}'")]
    UnsafeDirectory { path: String },
    #[error(transparent)]
    InvalidPath(#[from] SocketPathError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl ConnectSocketPathError {
    /// Return whether permission or directory protection kept the CLI out.
    fn is_permission_denied(&self) -> bool {
        matches!(self, Self::UnsafeDirectory { .. })
            || matches!(self, Self::Io(error) if error.kind() == io::ErrorKind::PermissionDenied)
    }

    /// Return whether this candidate is unavailable and the fallback may be tried.
    fn allows_fallback(&self) -> bool {
        self.is_permission_denied()
            || matches!(
                self,
                Self::Io(error)
                    if matches!(error.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound)
            )
    }
}

/// Failed connection attempts to the primary and optional fallback socket.
#[derive(Debug, Error)]
#[error(
    "could not connect to the daemon socket at '{SOCKET_FILE_PATH}': {source}{}; is the bindizr daemon running?",
    fallback.as_ref().map(|error| format!("; fallback '{FALLBACK_SOCKET_FILE_PATH}': {error}")).unwrap_or_default()
)]
struct ConnectDaemonSocketError {
    #[source]
    source: ConnectSocketPathError,
    fallback: Option<ConnectSocketPathError>,
}

/// The authenticated daemon socket targeted by the shutdown command.
#[derive(Debug)]
pub(crate) struct ShutdownSocket {
    path: &'static str,
    id: SocketFileId,
}

impl ShutdownSocket {
    /// Read the identity of the socket the shutdown request reached.
    async fn read(path: &'static str) -> Result<Self, CliError> {
        let metadata = fs::symlink_metadata(path).await.map_err(|error| {
            CliError::request_with_source(
                format!("could not inspect daemon socket at '{path}': {error}"),
                error,
            )
        })?;
        let id = SocketFileId::from_metadata(&metadata)
            .ok_or_else(|| CliError::request(format!("the daemon socket at '{path}' moved")))?;
        Ok(Self { path, id })
    }

    /// Return whether the daemon removed the socket it held while draining.
    pub(crate) async fn is_gone(&self) -> bool {
        match fs::symlink_metadata(self.path).await {
            Ok(metadata) => SocketFileId::from_metadata(&metadata) != Some(self.id),
            Err(error) => error.kind() == io::ErrorKind::NotFound,
        }
    }
}

/// Ask the daemon to stop and remember the socket whose removal completes it.
pub(crate) async fn send_shutdown()
-> Result<(DaemonResponse<MessageResponse>, ShutdownSocket), CliError> {
    with_control_timeout(async {
        let (socket_path, stream) = connect_to_daemon_socket().await?;
        let socket_file = ShutdownSocket::read(socket_path).await?;
        let response = send_connected_command(stream, DaemonCommand::Shutdown).await?;
        Ok((response, socket_file))
    })
    .await
}

/// Send a command the daemon answers from memory (status/lifecycle) under
/// a short deadline, so a wedged daemon cannot hang polling loops.
pub(crate) async fn send_control_command<T: DeserializeOwned>(
    command: DaemonCommand,
) -> Result<DaemonResponse<T>, CliError> {
    with_control_timeout(send_command(command)).await
}

/// Bound the time a lifecycle command can spend waiting on a daemon.
async fn with_control_timeout<T>(
    command: impl Future<Output = Result<T, CliError>>,
) -> Result<T, CliError> {
    const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

    time::timeout(CONTROL_TIMEOUT, command)
        .await
        .map_err(|error| {
            CliError::request_with_source(
                format!(
                    "the daemon did not answer within {} seconds",
                    CONTROL_TIMEOUT.as_secs()
                ),
                error,
            )
        })?
}

/// Send a command to the daemon and read its response, whose payload is
/// the `T` the command answers with.
pub(crate) async fn send_command<T: DeserializeOwned>(
    command: DaemonCommand,
) -> Result<DaemonResponse<T>, CliError> {
    let (_, stream) = connect_to_daemon_socket().await?;
    send_connected_command(stream, command).await
}

/// Send one command and decode its reply on an authenticated stream.
async fn send_connected_command<T: DeserializeOwned>(
    mut stream: UnixStream,
    command: DaemonCommand,
) -> Result<DaemonResponse<T>, CliError> {
    let json = serde_json::to_string(&command).map_err(|error| {
        CliError::request_with_source(format!("failed to serialize command: {error}"), error)
    })?;

    stream.write_all(json.as_bytes()).await.map_err(|error| {
        CliError::request_with_source(format!("failed to write to socket: {error}"), error)
    })?;
    stream.write_all(b"\n").await.map_err(|error| {
        CliError::request_with_source(format!("failed to write newline to socket: {error}"), error)
    })?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();

    reader.read_line(&mut response).await.map_err(|error| {
        CliError::request_with_source(format!("failed to read from socket: {error}"), error)
    })?;

    // An error reply is an `ErrorResponse` instead of a `DaemonResponse`,
    // so only a failed command parses here.
    if let Ok(error) = serde_json::from_str::<ErrorResponse>(&response) {
        return Err(CliError::from_daemon(error.code, error.error));
    }

    serde_json::from_str(&response).map_err(|error| {
        let error = socket::SocketDecodeError(error);
        CliError::request_with_source(format!("failed to parse response ({error})"), error)
    })
}

/// Open a connection to the daemon's control socket, refusing a daemon this
/// user may not drive (a socket another user planted in /tmp).
async fn connect_to_daemon_socket() -> Result<(&'static str, UnixStream), CliError> {
    let (socket_path, stream, directory) = try_connect_daemon_socket().await.map_err(|error| {
        let denied_path = if error.source.is_permission_denied() {
            Some(SOCKET_FILE_PATH)
        } else if error
            .fallback
            .as_ref()
            .is_some_and(ConnectSocketPathError::is_permission_denied)
        {
            Some(FALLBACK_SOCKET_FILE_PATH)
        } else {
            None
        };

        match denied_path {
            Some(path) => CliError::request_with_source(
                format!(
                    "permission denied on the daemon socket at '{path}': {error}; run the CLI as \
                     the daemon's user (for a package install, `sudo bindizr ...`)"
                ),
                error,
            ),
            None => CliError::daemon_unreachable(error),
        }
    })?;

    let peer_uid = stream
        .peer_cred()
        .map_err(|error| {
            CliError::request_with_source(
                format!("could not identify the daemon behind its socket: {error}"),
                error,
            )
        })?
        .uid();
    let own_uid = socket::read_own_uid().map_err(|error| {
        CliError::request_with_source(format!("could not read this process's uid: {error}"), error)
    })?;

    if !socket::is_trusted_directory_owner(&directory, peer_uid) {
        return Err(CliError::request(format!(
            "the socket directory at '{socket_path}' does not belong to the daemon's uid or root"
        )));
    }

    // Root drives another user's daemon on the primary socket only, as `sudo bindizr` does.
    if !socket::is_trusted_daemon(peer_uid, own_uid, socket_path) {
        let message = if own_uid == 0 {
            format!(
                "the daemon at '{socket_path}' runs as uid {peer_uid}, not root, and anyone can \
                 plant a socket under /tmp; run the CLI as that user, or remove a socket another \
                 user left there"
            )
        } else {
            format!(
                "the daemon at '{socket_path}' runs as uid {peer_uid}, neither this user nor root; \
                 run the CLI as that user, or remove a socket another user left there"
            )
        };
        return Err(CliError::request(message));
    }

    Ok((socket_path, stream))
}

/// Attempt an io-level connect, naming the path that answered and preserving
/// the error(s) so callers can tell a vanished socket apart from other failures.
async fn try_connect_daemon_socket()
-> Result<(&'static str, UnixStream, Metadata), ConnectDaemonSocketError> {
    match connect_at_path(SOCKET_FILE_PATH).await {
        Ok((stream, directory)) => Ok((SOCKET_FILE_PATH, stream, directory)),
        Err(error) if error.allows_fallback() => {
            match connect_at_path(FALLBACK_SOCKET_FILE_PATH).await {
                Ok((stream, directory)) => Ok((FALLBACK_SOCKET_FILE_PATH, stream, directory)),
                Err(fallback_error) => Err(ConnectDaemonSocketError {
                    source: error,
                    fallback: Some(fallback_error),
                }),
            }
        }
        Err(error) => Err(ConnectDaemonSocketError {
            source: error,
            fallback: None,
        }),
    }
}

/// Inspect the socket directory without following a symlink, then connect at that path.
async fn connect_at_path(
    socket_path: &str,
) -> Result<(UnixStream, Metadata), ConnectSocketPathError> {
    let parent = socket::socket_directory(socket_path)?;
    let directory = fs::symlink_metadata(parent).await?;
    if !directory.is_dir() || socket::directory_allows_other_writes(&directory) {
        return Err(ConnectSocketPathError::UnsafeDirectory {
            path: parent.display().to_string(),
        });
    }

    let stream = UnixStream::connect(socket_path).await?;
    Ok((stream, directory))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tokio::net::UnixListener;

    use super::*;

    /// Verify that a pathname with an unsafe parent is refused before using the stream.
    #[tokio::test]
    async fn connect_at_path_requires_a_private_directory() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("bindizr.sock");
        let socket_path = socket_path.to_str().unwrap();
        let _listener = UnixListener::bind(socket_path).unwrap();
        for mode in [0o770, 0o707] {
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(mode)).unwrap();
            let error = connect_at_path(socket_path).await.unwrap_err();

            assert!(matches!(
                error,
                ConnectSocketPathError::UnsafeDirectory { .. }
            ));
            assert!(error.allows_fallback());
        }

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(connect_at_path(socket_path).await.is_ok());
    }

    /// Verify that a malformed candidate is not classified as an unavailable socket.
    #[tokio::test]
    async fn connect_at_path_rejects_parentless_path() {
        let error = connect_at_path("/").await.unwrap_err();

        assert!(matches!(error, ConnectSocketPathError::InvalidPath(_)));
        assert!(!error.allows_fallback());
    }
}
