use std::time::Duration;

use crate::{
    cli::error::CliError,
    socket::{client::DaemonSocketClient, types::DaemonCommandKind},
};

const STOP_DEADLINE: Duration = Duration::from_secs(10);

/// Handle the `stop` subcommand: request daemon shutdown and wait until the
/// control socket stops answering.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let client = DaemonSocketClient::new();
    let res = client
        .send_control_command(DaemonCommandKind::Shutdown)
        .await?;
    println!("{}", res.message);

    let wait_until_gone = async {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if client.status().await.is_err() {
                break;
            }
        }
    };

    match tokio::time::timeout(STOP_DEADLINE, wait_until_gone).await {
        Ok(()) => {
            println!("Bindizr stopped.");
            Ok(())
        }
        Err(_) => Err(CliError::from(format!(
            "Bindizr did not stop within {} seconds",
            STOP_DEADLINE.as_secs()
        ))),
    }
}
