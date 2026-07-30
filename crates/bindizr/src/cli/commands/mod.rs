pub(super) mod config;
pub(super) mod doctor;
pub(super) mod record;
pub(super) mod restart;
pub(super) mod start;
pub(super) mod status;
pub(super) mod stop;
pub(super) mod token;
pub(super) mod tsig_key;
pub(super) mod zone;

use std::time::Duration;

use crate::{
    cli::error::CliError,
    socket::{client::DaemonSocketClient, types::DaemonStatusResponse},
};

/// Poll the daemon status every 100ms until `check` accepts it, bounded by
/// `deadline`. Returns `None` on expiry.
pub(super) async fn poll_daemon_status<T>(
    client: &DaemonSocketClient,
    deadline: Duration,
    check: impl Fn(Result<DaemonStatusResponse, CliError>) -> Option<T>,
) -> Option<T> {
    let wait = async {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Some(value) = check(client.status().await) {
                break value;
            }
        }
    };

    tokio::time::timeout(deadline, wait).await.ok()
}

/// Read command input from a file path, or from stdin when the path is `-`.
pub(super) fn read_input(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .map_err(|e| format!("Failed to read from stdin: {}", e))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read '{}': {}", path, e))
    }
}
