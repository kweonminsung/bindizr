use crate::{daemon::socket::client::DAEMON_SOCKET_CLIENT, log_debug};

pub fn handle_command() -> Result<(), String> {
    let res = DAEMON_SOCKET_CLIENT.send_command("stop", None)?;

    log_debug!("Stop command result: {:?}", res);

    println!("Bindizr service stopped successfully.");

    Ok(())
}
