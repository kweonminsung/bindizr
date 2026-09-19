use std::time::Duration;

use bindizr_core::outln;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, parse_response, print_payload},
    },
    socket::{
        client,
        types::{DaemonCommandKind, DaemonStatusResponse},
    },
};

/// The stop budget again, plus room for the replacement to open its database
/// and listeners.
const RESTART_DEADLINE: Duration = Duration::from_secs(40);

/// Handle the `restart` subcommand: re-exec the daemon in place and wait for
/// the replacement to answer.
pub(crate) async fn handle_command(output: OutputFormat) -> Result<(), CliError> {
    let before: DaemonStatusResponse = parse_response(
        &client::send_control_command(DaemonCommandKind::Status)
            .await?
            .data,
    )?;

    let res = client::send_control_command(DaemonCommandKind::Restart).await?;
    // The acknowledgement is progress, not the result: the command answers for
    // the replacement it waits for below.
    if output == OutputFormat::Table {
        outln!("{}", res.message);
    }

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
            match output {
                OutputFormat::Table => outln!(
                    "Bindizr restarted: pid {} (version {})",
                    pid,
                    status.version
                ),
                _ => {
                    let payload =
                        serde_json::to_value(&status).map_err(|e| CliError::from(e.to_string()))?;
                    print_payload(&payload, output)?
                }
            }
            Ok(())
        }
        None => Err(CliError::from(format!(
            "Bindizr did not come back within {} seconds after the restart request",
            RESTART_DEADLINE.as_secs()
        ))),
    }
}
