#[tokio::main]
async fn main() {
    #[cfg(not(any(unix)))]
    {
        eprintln!("Unsupported platform. Only Unix-like systems are supported");
        std::process::exit(1);
    }

    bindizr::execute().await;
}
