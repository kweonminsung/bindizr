use crate::{
    cli::{error::CliError, output::color},
    socket::client::DaemonSocketClient,
};

/// Handle the `status` subcommand by querying the daemon and printing its status.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let status = DaemonSocketClient::new().status().await?;

    println!("=== BINDIZR STATUS ===");

    println!("Status: {}", color::green("Running"));

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
