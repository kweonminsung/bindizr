use bindizr_service::{error::ErrorCode, types::ErrorResponse};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use crate::{
    cli::error::CliError,
    socket::{
        FALLBACK_SOCKET_FILE_PATH, SOCKET_FILE_PATH,
        types::{DaemonCommand, DaemonCommandKind, DaemonResponse, DaemonStatusResponse},
    },
};

/// Client for sending commands to the daemon over the Unix socket.
pub(crate) struct DaemonSocketClient;

impl DaemonSocketClient {
    pub(crate) fn new() -> Self {
        DaemonSocketClient
    }

    /// True only when nothing listens on either socket path; a timeout or
    /// garbled response may come from a live but wedged daemon.
    pub(crate) async fn daemon_socket_gone(&self) -> bool {
        fn gone(err: &std::io::Error) -> bool {
            matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            )
        }

        match try_connect_daemon_socket().await {
            Ok(_) => false,
            // An owner-only socket this user cannot open is a live daemon.
            Err((err, _)) if err.kind() == std::io::ErrorKind::PermissionDenied => false,
            // Primary refused/missing; the fallback was also tried.
            Err((_, Some(fallback_err))) => gone(&fallback_err),
            // Primary failed in an unexpected way; the fallback was not tried.
            Err((err, None)) => gone(&err),
        }
    }

    pub(crate) async fn status(&self) -> Result<DaemonStatusResponse, CliError> {
        let res = self.send_control_command(DaemonCommandKind::Status).await?;
        serde_json::from_value(res.data)
            .map_err(|e| CliError::from(format!("Failed to parse status response: {}", e)))
    }

    /// Send a command the daemon answers from memory (status/lifecycle) under
    /// a short deadline, so a wedged daemon cannot hang polling loops.
    pub(crate) async fn send_control_command(
        &self,
        command: DaemonCommandKind,
    ) -> Result<DaemonResponse, CliError> {
        const CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        tokio::time::timeout(CONTROL_TIMEOUT, self.send_command(command, ()))
            .await
            .map_err(|_| {
                CliError::from(format!(
                    "The daemon did not answer within {} seconds",
                    CONTROL_TIMEOUT.as_secs()
                ))
            })?
    }

    /// Send a command to the daemon and return its parsed response. `data` is
    /// the command's payload type; `()` for the commands that take none.
    pub(crate) async fn send_command(
        &self,
        command: DaemonCommandKind,
        data: impl serde::Serialize,
    ) -> Result<DaemonResponse, CliError> {
        let mut stream = connect_to_daemon_socket().await?;

        let cmd = DaemonCommand {
            command,
            data: serde_json::to_value(data)
                .map_err(|e| format!("Failed to serialize command payload: {}", e))?,
        };
        let json = serde_json::to_string(&cmd)
            .map_err(|e| format!("Failed to serialize command: {}", e))?;

        stream
            .write_all(json.as_bytes())
            .await
            .map_err(|e| format!("Failed to write to socket: {}", e))?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|e| format!("Error writing newline to socket: {}", e))?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();

        reader
            .read_line(&mut response)
            .await
            .map_err(|e| format!("Failed to read from socket: {}", e))?;

        // An error reply is an `ErrorResponse` instead of a `DaemonResponse`,
        // so only a failed command parses here.
        if let Ok(error) = serde_json::from_str::<ErrorResponse>(&response) {
            return Err(CliError {
                code: ErrorCode::parse(&error.code),
                message: error.error,
            });
        }

        Ok(serde_json::from_str(&response)
            .map_err(|e| format!("Failed to parse response: {}", e))?)
    }
}

async fn connect_to_daemon_socket() -> Result<UnixStream, CliError> {
    try_connect_daemon_socket()
        .await
        .map_err(|(err, fallback_err)| match fallback_err {
            // Owner-only by design: connecting grants global access.
            _ if err.kind() == std::io::ErrorKind::PermissionDenied => CliError::from(format!(
                "Permission denied on the daemon socket at '{}'. The socket is owner-only, so \
                 run the CLI as the user the daemon runs as (for a package install, `sudo \
                 bindizr ...`).",
                SOCKET_FILE_PATH
            )),
            Some(fallback_err) => CliError::from(format!(
                "Could not connect to the daemon socket at '{}' or fallback '{}': {}; fallback error: {}\nIs the bindizr daemon running?",
                SOCKET_FILE_PATH, FALLBACK_SOCKET_FILE_PATH, err, fallback_err
            )),
            None => CliError::from(format!(
                "Could not connect to the daemon socket at '{}': {}\nIs the bindizr daemon running?",
                SOCKET_FILE_PATH, err
            )),
        })
}

/// Io-level connect attempt, preserving the error(s) so callers can tell a
/// vanished socket apart from other failures.
async fn try_connect_daemon_socket() -> Result<UnixStream, (std::io::Error, Option<std::io::Error>)>
{
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
                Err(fallback_err) => Err((err, Some(fallback_err))),
            }
        }
        Err(err) => Err((err, None)),
    }
}
