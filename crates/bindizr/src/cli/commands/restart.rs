use std::time::Duration;

use crate::{
    cli::error::CliError,
    socket::{client::DaemonSocketClient, types::DaemonCommandKind},
};

/// Handle the `restart` subcommand: ask the daemon to re-exec itself and wait
/// for the replacement instance to answer.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let client = DaemonSocketClient::new();
    let before = client.status().await?;

    let res = client
        .send_command(DaemonCommandKind::Restart, None)
        .await?;
    println!("{}", res.message);

    // exec keeps the PID, so a changed start time is the restart signal.
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(status) = client.status().await
            && status.started_at_ms != before.started_at_ms
        {
            let pid = status
                .pid
                .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
            println!(
                "Bindizr restarted: pid {} (version {})",
                pid, status.version
            );
            return Ok(());
        }
    }

    Err(CliError::from(
        "Bindizr did not come back within 15 seconds after the restart request",
    ))
}
