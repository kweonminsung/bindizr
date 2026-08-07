//! Binary entry point: runs the ExternalDNS webhook adapter.

#[tokio::main]
async fn main() {
    bindizr_external_dns::execute().await;
}
