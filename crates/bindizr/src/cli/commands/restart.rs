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
    let wait_until_replaced = async {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(status) = client.status().await
                && status.started_at_ms != before.started_at_ms
            {
                break status;
            }
        }
    };

    match tokio::time::timeout(RESTART_DEADLINE, wait_until_replaced).await {
        Ok(status) => {
            let pid = status
                .pid
                .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
            println!(
                "Bindizr restarted: pid {} (version {})",
                pid, status.version
            );
            Ok(())
        }
        Err(_) => Err(CliError::from(format!(
            "Bindizr did not come back within {} seconds after the restart request",
            RESTART_DEADLINE.as_secs()
        ))),
    }
}
