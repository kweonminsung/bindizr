mod api;
mod cli;
mod config;
mod daemon;
mod database;
mod database_new;
mod logger;
mod rndc;
mod serializer;

#[tokio::main]
async fn main() {
    #[cfg(not(any(unix)))]
    {
        eprintln!("Unsupported platform. Only Unix-like systems are supported");
        std::process::exit(1);
    }

    cli::execute().await;
}
