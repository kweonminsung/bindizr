//! The ExternalDNS adapter process used by webhook scenarios.

use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use reqwest::Client;

use super::reserve_tcp_port;

/// A spawned bindizr-external-dns adapter process, killed on drop.
pub(crate) struct ExternalDnsAdapter {
    child: Child,
    pub(crate) base_url: String,
}

impl ExternalDnsAdapter {
    /// Spawn the adapter binary against `bindizr_url` on ephemeral localhost
    /// ports and wait until its webhook listener answers.
    pub(crate) async fn spawn(bindizr_url: &str, token: &str) -> Self {
        let webhook_port = reserve_tcp_port();
        let health_port = reserve_tcp_port();

        let mut command = Command::new(env!("CARGO_BIN_EXE_bindizr-e2e-external-dns"));
        command
            .arg("--bindizr-url")
            .arg(bindizr_url)
            .arg("--listen-addr")
            .arg(format!("127.0.0.1:{webhook_port}"))
            .arg("--health-listen-addr")
            .arg(format!("127.0.0.1:{health_port}"))
            .arg("--log-level")
            .arg("error")
            .arg("--token")
            .arg(token);

        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start bindizr-external-dns binary");

        let base_url = format!("http://127.0.0.1:{webhook_port}");
        let client = Client::new();
        for _ in 0..100 {
            if let Some(status) = child.try_wait().expect("failed to check adapter status") {
                panic!("bindizr-external-dns exited before it was ready: {status}");
            }
            // Any HTTP response means the webhook listener is up.
            if client.get(&base_url).send().await.is_ok() {
                return Self { child, base_url };
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        panic!("bindizr-external-dns did not become ready");
    }
}

impl Drop for ExternalDnsAdapter {
    /// Stop the external-dns adapter process when the test fixture is dropped.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
