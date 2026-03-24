mod api;
mod cli;
mod config;
mod database;
mod dns;
mod logger;
mod service;
mod socket;

#[tokio::main]
async fn main() {
    #[cfg(not(any(unix)))]
    {
        eprintln!("Unsupported platform. Only Unix-like systems are supported");
        std::process::exit(1);
    }

    cli::execute().await;
}
