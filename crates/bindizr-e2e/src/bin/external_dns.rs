#[tokio::main]
async fn main() {
    bindizr_external_dns::execute().await;
}
