mod api;
mod cli;
mod config;
mod database;
mod logger;
mod rndc;
mod serializer;

use cli::{execute, parser::Args};
use std::env;

#[tokio::main]
async fn main() {
    #[cfg(not(any(windows, unix)))]
    {
        eprintln!("Unsupported platform. Only Windows and Unix-like systems are supported");
        std::process::exit(1);
    }

    // Process command line arguments
    let args = Args::process_args(env::args());

    execute(&args).await;
}
