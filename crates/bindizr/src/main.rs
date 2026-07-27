//! Binary entry point: runs the bindizr CLI.

#[tokio::main]
async fn main() {
    bindizr::execute().await;
}
