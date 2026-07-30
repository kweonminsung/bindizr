use std::time::Duration;

use crate::{
    cli::error::CliError,
    socket::{client::DaemonSocketClient, types::DaemonCommandKind},
};

/// Handle the `stop` subcommand: request daemon shutdown and wait until the
/// control socket stops answering.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let client = DaemonSocketClient::new();
    let res = client
        .send_command(DaemonCommandKind::Shutdown, None)
        .await?;
    println!("{}", res.message);

    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if client.status().await.is_err() {
            println!("Bindizr stopped.");
            return Ok(());
        }
    }

    Err(CliError::from("Bindizr did not stop within 10 seconds"))
}
