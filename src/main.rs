mod api;
mod cli;
mod config;
mod database;
mod logger;
mod rndc;
mod serializer;
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
