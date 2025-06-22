use crate::daemon::socket::{
    dto::{DaemonCommand, DaemonResponse},
    socket::SOCKET_FILE_PATH,
};
use lazy_static::lazy_static;
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    sync::Mutex,
};

pub fn initialize() {
    lazy_static::initialize(&DAEMON_SOCKET_CLIENT);
}

pub struct DaemonSocketClient {
    stream: Mutex<UnixStream>,
}

impl DaemonSocketClient {
    fn new() -> Self {
        let stream = UnixStream::connect(SOCKET_FILE_PATH);

        if let Err(e) = stream {
            eprintln!(
                "Could not connect to the daemon socket: {}\nIs the bindizr daemon running?",
                e
            );
            std::process::exit(1);
        };

        DaemonSocketClient {
            stream: Mutex::new(stream.unwrap()),
        }
    }

    pub fn send_command(
        &self,
        command: &str,
        data: Option<serde_json::Value>,
    ) -> Result<DaemonResponse, String> {
        // Serialize the command to JSON
        let cmd = DaemonCommand {
            command: command.to_string(),
            data: data.unwrap_or(serde_json::Value::Null),
        };
        let json = serde_json::to_string(&cmd)
            .map_err(|e| format!("Failed to serialize command: {}", e))?;

        // Connect and send the command
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| "Failed to lock stream".to_string())?;
        stream
            .write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write to socket: {}", e))?;
        stream
            .write_all(b"\n")
            .map_err(|e| format!("Error writing newline to socket: {}", e))?;

        // Read the response
        let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        let mut response = String::new();

        reader
            .read_line(&mut response)
            .map_err(|e| format!("Failed to read from socket: {}", e))?;

        // Deserialize the response
        serde_json::from_str(&response).map_err(|e| format!("Failed to parse response: {}", e))
    }
}

lazy_static! {
    pub static ref DAEMON_SOCKET_CLIENT: DaemonSocketClient = DaemonSocketClient::new();
}
