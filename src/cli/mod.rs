pub mod daemon;
pub mod parser;
pub mod reload;
pub mod start;
pub mod stop;
pub mod token;

#[cfg(test)]
mod tests;

use crate::{config, database};
use parser::Args;
use std::process::exit;

fn pre_bootstrap(skip_for_running_daemon: bool) {
    // Skip initialization if the daemon is running and the flag is set
    if skip_for_running_daemon && daemon::is_running() {
        return;
    }

    config::initialize();
    database::initialize();
}

pub async fn execute(args: &Args) {
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
