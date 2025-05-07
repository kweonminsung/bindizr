mod api;
mod database;
mod env;
mod parser;

#[tokio::main]
async fn main() {
    // Load environment variables
    env::initialize();

    // Initialize API server
    api::initialize().await;
}
