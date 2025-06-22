use crate::{cli::bootstrap, daemon::process};

pub fn help_message() -> String {
    "Usage: bindizr start [OPTIONS]\n\
    \n\
    Start the bindizr service\n\
    \n\
    Options:\n\
    -f, --foreground   Run in foreground (default is background)\n\
    -s, --silent       Run in silent mode (no stdout)\n\
    -c, --config <FILE>  Path to the configuration file (default: /etc/bindizr/bindizr.conf)\n\
    -h, --help         Show this help message"
        .to_string()
}

pub async fn handle_command(args: &crate::cli::Args) -> Result<(), String> {
    let config_file = if args.has_option("-c") || args.has_option("--config") {
        args.get_option_value("-c")
            .or_else(|| args.get_option_value("--config"))
            .map(|s| s.as_str())
    } else {
        None
    };

    if args.has_option("-f") || args.has_option("--foreground") {
        // Run in foreground mode
        if args.has_option("-s") || args.has_option("--silent") {
            // Silent mode
            bootstrap(true, config_file).await?;
        } else {
            bootstrap(false, config_file).await?;
        }
    } else {
        // Run in background mode
        process::start();
    }

    Ok(())
}
