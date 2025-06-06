pub(crate) mod daemon;
pub(crate) mod dns;
pub(crate) mod parser;
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
        "stop" => pre_bootstrap(true),
        "dns" => pre_bootstrap(false),
        "token" => pre_bootstrap(false),
        _ => pre_bootstrap(false),
    }

    // Execute command
    match args.command.as_str() {
        "start" => start::execute(&args).await,
        "stop" => stop::execute(&args),
        "dns" => {
            if let Err(e) = dns::handle_command(&args) {
                eprintln!("Error: {}", e);
                exit(1);
            }
        }
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
