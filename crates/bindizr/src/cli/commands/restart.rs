use std::time::Duration;

use bindizr_core::outln;
use bindizr_service::types::MessageResponse;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, print_payload},
    },
    socket::{
        client,
        types::{DaemonCommand, DaemonStatusResponse},
    },
};

/// The stop budget again, plus room for the replacement to open its database
/// and listeners.
const RESTART_DEADLINE: Duration = Duration::from_secs(40);

/// Handle the `restart` subcommand: re-exec the daemon in place and wait for
/// the replacement to answer.
pub(crate) async fn handle_command(output: OutputFormat) -> Result<(), CliError> {
    let before = client::send_control_command::<DaemonStatusResponse>(DaemonCommand::Status)
        .await?
        .data;
    let res = client::send_control_command::<MessageResponse>(DaemonCommand::Restart).await?;
    // The acknowledgement is progress, not the result: the command answers for
    // the replacement it waits for below.
    if output == OutputFormat::Table {
        outln!("{}", res.message);
    }
    // exec keeps the PID, so a changed start time is the restart signal.
    let replaced = super::poll_with_deadline(RESTART_DEADLINE, async || {
        client::send_control_command::<DaemonStatusResponse>(DaemonCommand::Status)
            .await
            .ok()
            .map(|response| response.data)
            .filter(|status| status.started_at_ms != before.started_at_ms)
    })
    .await;
    match replaced {
        Some(status) => {
            let pid = status
                .pid
                .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
            match output {
                OutputFormat::Table => outln!(
                    "Bindizr restarted: pid {} (version {})",
                    pid,
                    status.version
                ),
                _ => print_payload(&status, output)?,
            }
            Ok(())
        }
        None => Err(CliError::request(format!(
            "Bindizr did not come back within {} seconds after the restart request",
            RESTART_DEADLINE.as_secs()
        ))),
    }
}
