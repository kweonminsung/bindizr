use std::{
    fs,
    net::{TcpListener, UdpSocket},
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;

pub(crate) struct TestApp {
    _temp_dir: TempDir,
    child: Child,
    client: Client,
    base_url: String,
}

impl TestApp {
    pub(crate) async fn start() -> Self {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let api_port = reserve_tcp_port();
        let dns_port = reserve_dns_port();
        let db_path = temp_dir.path().join("bindizr.sqlite");
        fs::File::create(&db_path).expect("failed to create sqlite file");

        let config_path = temp_dir.path().join("bindizr.conf.toml");
        write_config(&config_path, api_port, dns_port, &db_path);

        let mut child = Command::new(env!("CARGO_BIN_EXE_bindizr"))
            .arg("start")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start bindizr binary");

        let client = Client::new();
        let base_url = format!("http://127.0.0.1:{api_port}");
        wait_for_api(&client, &base_url, &mut child).await;

        Self {
            _temp_dir: temp_dir,
            child,
            client,
            base_url,
        }
    }

    pub(crate) async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.request(method, url);
        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request.send().await.expect("failed to send HTTP request");
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .expect("failed to read HTTP response body");

        let body = if bytes.is_empty() {
            json!(null)
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)))
        };

        (status, body)
    }

    pub(crate) async fn create_test_zone(&self) -> Value {
        let request = json!({
            "name": "example.com",
            "primary_ns": "ns1.example.com",
            "admin_email": "admin@example.com",
            "ttl": 3600,
            "serial": 2023010101,
            "refresh": 7200,
            "retry": 3600,
            "expire": 604800,
            "minimum_ttl": 86400
        });
        let (status, body) = self.request(Method::POST, "/zones", Some(request)).await;
        assert_eq!(status, StatusCode::CREATED);
        body["zone"].clone()
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        // Ensure the child process is terminated even if the test panics.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn reserve_tcp_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("failed to bind ephemeral TCP port")
        .local_addr()
        .expect("failed to read ephemeral TCP port")
        .port()
}

fn reserve_dns_port() -> u16 {
    for _ in 0..10 {
        let tcp =
            TcpListener::bind(("127.0.0.1", 0)).expect("failed to bind ephemeral DNS TCP port");
        let port = tcp
            .local_addr()
            .expect("failed to read ephemeral DNS TCP port")
            .port();

        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }

    panic!("failed to reserve a DNS port available for both TCP and UDP");
}

fn write_config(config_path: &Path, api_port: u16, dns_port: u16, db_path: &Path) {
    let config = format!(
        r#"
[api]
listen_addr = "127.0.0.1"
listen_port = {api_port}
require_authentication = false

[database]
type = "sqlite"

[database.mysql]
server_url = ""

[database.sqlite]
file_path = "{}"

[database.postgresql]
server_url = ""

[dns]
listen_addr = "127.0.0.1"
listen_port = {dns_port}
secondary_addrs = ""
notify_after_update = false
notify_on_startup = false
notify_retries = 0
notify_timeout_secs = 1
nsupdate_tsig_key = ""

[logging]
log_level = "error"
"#,
        db_path.display()
    );

    fs::write(config_path, config).expect("failed to write bindizr config");
}

async fn wait_for_api(client: &Client, base_url: &str, child: &mut Child) {
    for _ in 0..100 {
        if let Some(status) = child.try_wait().expect("failed to check child status") {
            panic!("bindizr exited before API was ready: {status}");
        }

        if let Ok(response) = client.get(base_url).send().await {
            if response.status() == StatusCode::OK {
                return;
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("bindizr API did not become ready");
}
