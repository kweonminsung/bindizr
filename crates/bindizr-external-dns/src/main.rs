//! Binary entry point: runs the ExternalDNS webhook adapter.

/// Run the external-dns adapter entry point.
#[tokio::main]
async fn main() {
    bindizr_external_dns::execute().await;
}
