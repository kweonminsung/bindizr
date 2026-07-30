use crate::{cli::error::CliError, socket::client::DaemonSocketClient};

/// Handle the `status` subcommand by querying the daemon and printing its status.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let status = DaemonSocketClient::new().status().await?;

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
