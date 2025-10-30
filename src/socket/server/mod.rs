mod dns;
mod status;
mod token;

use crate::socket::dto::{DaemonCommand, DaemonCommandKind};
use crate::socket::socket::SOCKET_FILE_PATH;
use crate::{log_error, log_info};
use serde_json::json;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

async fn handle_client(stream: UnixStream) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    if reader.read_line(&mut line).await.is_ok() {
        let parsed: Result<DaemonCommand, _> = serde_json::from_str(&line);

        let raw_response = match parsed {
            Ok(cmd) => match cmd.command {
                DaemonCommandKind::Status => status::get_status(),
                DaemonCommandKind::TokenCreate => token::create_token(&cmd.data).await,
                DaemonCommandKind::TokenList => token::list_tokens().await,
                DaemonCommandKind::TokenDelete => token::delete_token(&cmd.data).await,
                DaemonCommandKind::DnsWriteConfig => dns::write_dns_config().await,
                DaemonCommandKind::DnsReload => dns::reload_dns_config(),
                DaemonCommandKind::DnsStatus => dns::get_dns_status(),
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

pub async fn initialize() -> Result<(), String> {
    if fs::metadata(SOCKET_FILE_PATH).await.is_ok() {
        match UnixStream::connect(SOCKET_FILE_PATH).await {
            Ok(_) => {
                return Err("Bindizr is already running.".to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                // Socket file exists but no process is listening, so we can safely remove it.
                if let Err(e) = fs::remove_file(SOCKET_FILE_PATH).await {
                    return Err(format!("Failed to remove stale socket file: {}", e));
                }
            }
            Err(e) => {
                return Err(format!("Failed to check socket status: {}", e));
            }
        }
    }

    let listener = UnixListener::bind(SOCKET_FILE_PATH)
        .map_err(|e| format!("Failed to bind Unix socket: {}", e))?;

    log_info!("Daemon socket server listening on {}", SOCKET_FILE_PATH);

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

fn json_response_error(msg: &str) -> String {
    json!({
        "message": msg,
        "data": null
    })
    .to_string()
}
