use std::time::Duration;

use crate::{
    cli::error::CliError,
    socket::{client::DaemonSocketClient, types::DaemonCommandKind},
};

const RESTART_DEADLINE: Duration = Duration::from_secs(15);

/// Handle the `restart` subcommand: re-exec the daemon in place and wait for
/// the replacement to answer.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let client = DaemonSocketClient::new();
    let before = client.status().await?;

    let res = client
        .send_control_command(DaemonCommandKind::Restart)
        .await?;
    println!("{}", res.message);

    // exec keeps the PID, so a changed start time is the restart signal.
    let replaced = super::poll_daemon_status(&client, RESTART_DEADLINE, |status| match status {
        Ok(status) if status.started_at_ms != before.started_at_ms => Some(status),
        _ => None,
    })
    .await;

    match replaced {
        Some(status) => {
            let pid = status
                .pid
                .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
            println!(
                "Bindizr restarted: pid {} (version {})",
                pid, status.version
            );
            Ok(())
        }
        None => Err(CliError::from(format!(
            "Bindizr did not come back within {} seconds after the restart request",
            RESTART_DEADLINE.as_secs()
        ))),
    }
}
