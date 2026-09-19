use std::time::Duration;

use bindizr_core::outln;

use crate::{
    cli::error::CliError,
    socket::{client, types::DaemonCommandKind},
};

/// Longer than the daemon's own drain budget plus the delay before it acts on
/// the request, so a maximal drain is not reported as a timeout.
const STOP_DEADLINE: Duration = Duration::from_secs(20);

/// Handle the `stop` subcommand: request shutdown and wait until the daemon
/// socket stops answering.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let res = client::send_control_command(DaemonCommandKind::Shutdown).await?;
    outln!("{}", res.message);

    let stopped = super::poll_with_deadline(STOP_DEADLINE, async || {
        client::is_daemon_socket_gone().await.then_some(())
    })
    .await;

    match stopped {
        Some(()) => {
            outln!("Bindizr stopped.");
            Ok(())
        }
        None => Err(CliError::from(format!(
            "Bindizr did not stop within {} seconds",
            STOP_DEADLINE.as_secs()
        ))),
    }
}
