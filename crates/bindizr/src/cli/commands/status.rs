use bindizr_core::log_debug;

use crate::{
    cli::error::CliError,
    socket::{
        client::DaemonSocketClient,
        types::{DaemonCommandKind, DaemonStatusResponse},
    },
};

/// Handle the `status` subcommand by querying the daemon and printing its status.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let client = DaemonSocketClient::new();

    let res = client.send_command(DaemonCommandKind::Status, None).await?;

    log_debug!("Status command result: {:?}", res);

    let status: DaemonStatusResponse = serde_json::from_value(res.data)
        .map_err(|e| format!("Failed to parse status response: {}", e))?;

    println!("=== BINDIZR STATUS ===");

    println!("Status: \x1b[32mRunning\x1b[0m");

    let pid = match status.pid {
        Some(pid) => pid.to_string(),
        None => "Unknown".to_string(),
    };
    println!("PID: {}", pid);

    println!("Version: {}", status.version);
    println!();
    println!("Run 'bindizr config list' to see the loaded configuration.");
    Ok(())
}
