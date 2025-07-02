mod dns;
mod status;
mod stop;
mod token;

use crate::daemon::socket::dto::DaemonCommand;
use crate::daemon::socket::socket::SOCKET_FILE_PATH;
use crate::{log_error, log_info};
use serde_json::json;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};

async fn handle_client(mut stream: UnixStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();

    if reader.read_line(&mut line).is_ok() {
        let parsed: Result<DaemonCommand, _> = serde_json::from_str(&line);

        let raw_response = match parsed {
            Ok(cmd) => match cmd.command.as_str() {
                "stop" => stop::shutdown(),
                "status" => status::get_status(),
                "token_create" => token::create_token(&cmd.data).await,
                "token_list" => token::list_tokens().await,
                "token_delete" => token::delete_token(&cmd.data).await,
                "dns_write_config" => dns::write_dns_config(),
                "dns_reload" => dns::reload_dns_config(),
                "dns_status" => dns::get_dns_status(),
                _ => Err("Unsupported daemon command".to_string()),
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

        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(b"\n");
    }
}

pub fn initialize() -> Result<(), String> {
    let _ = fs::remove_file(SOCKET_FILE_PATH); // Remove old socket file

    let listener = UnixListener::bind(SOCKET_FILE_PATH)
        .map_err(|e| format!("Failed to bind Unix socket: {}", e))?;

    log_info!("Daemon socket server listening on {}", SOCKET_FILE_PATH);

    std::thread::spawn(async move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => handle_client(stream).await,
                Err(e) => {
                    log_error!("Error: {}", e);
                    continue;
                }
            }
        }
    });

    Ok(())
}

pub fn shutdown() {
    log_info!("Shutting down daemon socket server");

    if let Err(e) = fs::remove_file(SOCKET_FILE_PATH) {
        log_error!("Failed to remove socket file: {}", e);
    }
}

fn json_response_error(msg: &str) -> String {
    json!({
        "message": msg,
        "data": null
    })
    .to_string()
}
