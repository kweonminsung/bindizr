pub(crate) mod daemon;
pub(crate) mod parser;
pub(crate) mod reload;
pub(crate) mod start;
pub(crate) mod stop;
pub(crate) mod token;

use crate::{config, database};
use parser::Args;
use std::process::exit;

fn pre_bootstrap(skip_for_running_daemon: bool) {
    // Skip initialization if the daemon is running and the flag is set
    if skip_for_running_daemon || daemon::is_running() {
        return;
    }

    config::initialize();
    database::initialize();
}

pub(crate) async fn execute(args: &Args) {
    match args.command.as_str() {
        "start" => pre_bootstrap(false),
        "stop" | "reload" => pre_bootstrap(true),
        "token" => pre_bootstrap(false),
        _ => pre_bootstrap(false),
    }

    // Execute command
    match args.command.as_str() {
        "start" => start::execute(&args).await,
        "stop" => stop::execute(&args),
        "reload" => reload::execute(&args),
        "token" => {
            if let Err(e) = token::handle_command(&args) {
                eprintln!("Error: {}", e);
                exit(1);
            }
        }
        _ => {
            eprintln!("Unsupported command: {}", args.command);
            exit(1);
        }
    }
}
