use crate::cli::daemon;

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
    daemon::stop();

    Ok(())
}
