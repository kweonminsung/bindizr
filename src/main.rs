mod api;
mod config;
mod database;
mod rndc;
mod serializer;

#[tokio::main]
async fn main() {
    // load config
    config::initialize();

    serializer::initialize();

    // initialize API server
    api::initialize().await;
}
