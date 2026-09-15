//! Binary entry point: runs the bindizr CLI.

/// Run the bindizr command-line entry point.
#[tokio::main]
async fn main() {
    bindizr::execute().await;
}
