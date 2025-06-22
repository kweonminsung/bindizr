use crate::{daemon::socket::client::DAEMON_SOCKET_CLIENT, log_debug};

pub fn help_message() -> String {
    "Usage: bindizr stop\n\
    \n\
    Stop the bindizr service\n\
    \n\
    Options:\n\
    -h, --help         Show this help message"
        .to_string()
}

pub fn handle_command() -> Result<(), String> {
    let res = DAEMON_SOCKET_CLIENT.send_command("stop", None)?;

    log_debug!("Stop command result: {:?}", res);

    println!("Bindizr service stopped successfully.");

    Ok(())
}
