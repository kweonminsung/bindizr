use crate::cli::{bootstrap, daemon};

pub fn help_message() -> String {
    "Usage: bindizr start [OPTIONS]\n\
    \n\
    Start the bindizr service\n\
    \n\
    Options:\n\
    -f, --foreground   Run in foreground (default is background)\n\
    -h, --help         Show this help message"
        .to_string()
}

pub async fn handle_command(args: &crate::cli::Args) -> Result<(), String> {
    if args.has_option("-f") || args.has_option("--foreground") {
        // Run in foreground mode
        bootstrap().await?;
    } else {
        // Run in background mode
        daemon::start();
    }

    Ok(())
}
