use std::time::Duration;

use bindizr_core::outln;

use crate::{
    cli::{error::CliError, output::parse_response},
    socket::{
        client,
        types::{DaemonCommandKind, DaemonStatusResponse},
    },
};

const RESTART_DEADLINE: Duration = Duration::from_secs(15);

/// Handle the `restart` subcommand: re-exec the daemon in place and wait for
/// the replacement to answer.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let before: DaemonStatusResponse = parse_response(
        &client::send_control_command(DaemonCommandKind::Status)
            .await?
            .data,
    )?;

    let res = client::send_control_command(DaemonCommandKind::Restart).await?;
    outln!("{}", res.message);

    // exec keeps the PID, so a changed start time is the restart signal.
    let replaced = super::poll_with_deadline(RESTART_DEADLINE, async || {
        let Ok(response) = client::send_control_command(DaemonCommandKind::Status).await else {
            return None;
        };
        parse_response::<DaemonStatusResponse>(&response.data)
            .ok()
            .filter(|status| status.started_at_ms != before.started_at_ms)
    })
    .await;

    match replaced {
        Some(status) => {
            let pid = status
                .pid
                .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
            outln!(
                "Bindizr restarted: pid {} (version {})",
                pid,
                status.version
            );
            Ok(())
        }
        None => Err(CliError::from(format!(
            "Bindizr did not come back within {} seconds after the restart request",
            RESTART_DEADLINE.as_secs()
        ))),
    }
}
