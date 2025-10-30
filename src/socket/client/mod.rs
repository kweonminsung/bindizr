use crate::socket::{
    dto::{DaemonCommand, DaemonCommandKind, DaemonResponse},
    socket::SOCKET_FILE_PATH,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

pub struct DaemonSocketClient;

impl Default for DaemonSocketClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonSocketClient {
    pub fn new() -> Self {
        DaemonSocketClient
    }

    pub async fn send_command(
        &self,
        command: DaemonCommandKind,
        data: Option<serde_json::Value>,
    ) -> Result<DaemonResponse, String> {
        // Connect to the socket
        let stream = UnixStream::connect(SOCKET_FILE_PATH).await.map_err(|e| {
            format!(
                "Could not connect to the daemon socket: {}\nIs the bindizr daemon running?",
                e
            )
        })?;

        // Serialize the command to JSON
        let cmd = DaemonCommand {
            command,
            data: data.unwrap_or(serde_json::Value::Null),
        };
        let json = serde_json::to_string(&cmd)
            .map_err(|e| format!("Failed to serialize command: {}", e))?;

        // Send the command
        let mut writer = stream;
        writer
            .write_all(json.as_bytes())
            .await
            .map_err(|e| format!("Failed to write to socket: {}", e))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| format!("Error writing newline to socket: {}", e))?;

        // Read the response
        let mut reader = BufReader::new(writer);
        let mut response = String::new();

        reader
            .read_line(&mut response)
            .await
            .map_err(|e| format!("Failed to read from socket: {}", e))?;

        // Deserialize the response
        serde_json::from_str(&response).map_err(|e| format!("Failed to parse response: {}", e))
    }
}
