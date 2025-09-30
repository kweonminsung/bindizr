use crate::{log_debug, socket::client::DaemonSocketClient};

pub async fn handle_command() -> Result<(), String> {
    let client = DaemonSocketClient::new();
    let res = client.send_command("stop", None).await?;

    log_debug!("Stop command result: {:?}", res);

    println!("Bindizr service stopped successfully.");

    Ok(())
}
