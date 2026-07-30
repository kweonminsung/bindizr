use std::time::Duration;

use crate::{
    cli::error::CliError,
    socket::{client::DaemonSocketClient, types::DaemonCommandKind},
};

const STOP_DEADLINE: Duration = Duration::from_secs(10);

/// Handle the `stop` subcommand: request shutdown and wait until the daemon
/// socket stops answering.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let client = DaemonSocketClient::new();
    let res = client
        .send_control_command(DaemonCommandKind::Shutdown)
        .await?;
    println!("{}", res.message);

    let stopped = super::poll_with_deadline(STOP_DEADLINE, async || {
        client.daemon_socket_gone().await.then_some(())
    })
    .await;

    match stopped {
        Some(()) => {
            println!("Bindizr stopped.");
            Ok(())
        }
        None => Err(CliError::from(format!(
            "Bindizr did not stop within {} seconds",
            STOP_DEADLINE.as_secs()
        ))),
    }
}
