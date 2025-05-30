use crate::cli::daemon::{Daemon, DaemonControl};

pub(crate) fn help_message() -> String {
    "Usage: bindizr stop\n\
    \n\
    Stop the bindizr service\n\
    \n\
    Options:\n\
    -h, --help         Show this help message"
        .to_string()
}

pub(crate) fn execute(_args: &crate::cli::Args) {
    Daemon::stop();
}
