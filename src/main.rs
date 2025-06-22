mod api;
mod cli;
mod config;
mod daemon;
mod database;
mod logger;
mod rndc;
mod serializer;

use cli::{execute, parser::Args};
use std::env;

#[tokio::main]
async fn main() {
    #[cfg(not(any(unix)))]
    {
        eprintln!("Unsupported platform. Only Unix-like systems are supported");
        std::process::exit(1);
    }

    // Process command line arguments
    let args = Args::process_args(env::args());

    execute(&args).await;
}
