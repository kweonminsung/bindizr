mod api;
mod database;
mod env;
mod rndc;
mod serializer;

#[tokio::main]
async fn main() {
    // load environment variables
    env::initialize();

    serializer::initialize();

    // initialize API server
    api::initialize().await;
}
