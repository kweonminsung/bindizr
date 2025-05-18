mod api;
mod database;
mod env;
mod rndc;
mod serializer;

#[tokio::main]
async fn main() {
    // Load environment variables
    env::initialize();

    serializer::initialize();

    // Initialize API server
    api::initialize().await;
}
