use bindizr_service::error::ErrorCode;
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
    /// Create a new [`DaemonSocketClient`].
    pub(crate) fn new() -> Self {
        DaemonSocketClient
    }

    /// Query the daemon's status.
    pub(crate) async fn status(&self) -> Result<DaemonStatusResponse, CliError> {
        let res = self.send_command(DaemonCommandKind::Status, None).await?;
        serde_json::from_value(res.data)
            .map_err(|e| CliError::from(format!("Failed to parse status response: {}", e)))
    }

    /// Send a command to the daemon and return its parsed response.
    pub(crate) async fn send_command(
        &self,
        command: DaemonCommandKind,
        data: Option<serde_json::Value>,
    ) -> Result<DaemonResponse, CliError> {
        let mut stream = connect_to_daemon_socket().await?;

        let cmd = DaemonCommand {
            command,
            data: data.unwrap_or(serde_json::Value::Null),
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

        let response: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        if let Some(error) = response.get("error").and_then(serde_json::Value::as_str) {
            let code = response
                .get("code")
                .and_then(serde_json::Value::as_str)
                .and_then(ErrorCode::parse);
            return Err(CliError {
                code,
                message: error.to_string(),
            });
        }

        Ok(serde_json::from_value(response)
            .map_err(|e| format!("Failed to parse response: {}", e))?)
    }
}

async fn connect_to_daemon_socket() -> Result<UnixStream, CliError> {
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
            UnixStream::connect(FALLBACK_SOCKET_FILE_PATH)
                .await
                .map_err(|fallback_err| {
                CliError::from(format!(
                    "Could not connect to the daemon socket at '{}' or fallback '{}': {}; fallback error: {}\nIs the bindizr daemon running?",
                    SOCKET_FILE_PATH, FALLBACK_SOCKET_FILE_PATH, err, fallback_err
                ))
            })
        }
        Err(err) => Err(CliError::from(format!(
            "Could not connect to the daemon socket at '{}': {}\nIs the bindizr daemon running?",
            SOCKET_FILE_PATH, err
        ))),
    }
}
