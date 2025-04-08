mod api;
mod database;
mod env;

#[tokio::main]
async fn main() {
    // Load environment variables
    env::initialize();

    // Initialize database session
    database::initialize().await;

    // Initialize API server
    api::initialize().await;
}
