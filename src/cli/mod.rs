pub(crate) mod daemon;
pub(crate) mod dns;
pub(crate) mod parser;
pub(crate) mod start;
pub(crate) mod stop;
pub(crate) mod token;

use crate::{api, config, database, log_warn, logger, serializer};
use parser::Args;

fn pre_bootstrap(skip_database_init: bool) {
    config::initialize();
    logger::initialize();

    // Skip initialization if the daemon is running and the flag is set
    if skip_database_init || daemon::is_running() {
        return;
    }

    database::initialize();
}

async fn bootstrap() {
    serializer::initialize();
    api::initialize().await;
}

pub(crate) async fn execute(args: &Args) {
    if args.command.as_str() == "bootstrap" {
        pre_bootstrap(false);
    } else {
        pre_bootstrap(true);
    }

    // Execute command
    match args.command.as_str() {
        "start" => start::execute(&args).await,
        "stop" => stop::execute(&args),
        "dns" => {
            if let Err(e) = dns::handle_command(&args) {
                log_warn!("Error: {}", e);
                std::process::exit(1);
            }
        }
        "token" => {
            if let Err(e) = token::handle_command(&args) {
                log_warn!("Error: {}", e);
                std::process::exit(1);
            }
        }
        "bootstrap" => bootstrap().await,
        _ => {
            log_warn!("Unsupported command: {}", args.command);
            std::process::exit(1);
        }
    }
}
