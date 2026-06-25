use std::{
    collections::HashMap,
    env, fs,
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;

mod assertions;
mod dns;
pub(crate) mod notify;

pub(crate) use assertions::{assert_cli_failure_contains, assert_cli_success};
use dns::{dns_expected_value, dns_key_from_record, dns_record_type, wait_for_dns_records};

const COMPOSE_FILE: &str = "docker-compose.yml";
const COMPOSE_PROJECT_NAME: &str = "bindizr-e2e-dns";
const COMPOSE_API_BASE_URL: &str = "http://127.0.0.1:8000";
const DNS_VERIFICATION_ENV: &str = "BINDIZR_E2E_VERIFY_DNS";
const SECONDARY_PORTS: [u16; 2] = [1053, 1054];
const COMPOSE_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
static COMPOSE_STACK: OnceLock<ComposeStack> = OnceLock::new();
static TEST_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
static RUN_ID: OnceLock<String> = OnceLock::new();

pub(crate) struct TestApp {
    runtime: Option<TestRuntime>,
    client: Client,
    base_url: String,
    dns_secondary_ports: Vec<u16>,
    namespace: String,
}

enum TestRuntime {
    Local { temp_dir: TempDir, child: Child },
    Compose(&'static ComposeStack),
}

impl TestApp {
    pub(crate) async fn start() -> Self {
        if dns_verification_enabled() {
            Self::start_compose().await
        } else {
            Self::start_local().await
        }
    }

    async fn start_local() -> Self {
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
            runtime: Some(TestRuntime::Local { temp_dir, child }),
            client,
            base_url,
            dns_secondary_ports: Vec::new(),
            namespace: test_namespace(),
        }
    }

    async fn start_compose() -> Self {
        let compose_stack = COMPOSE_STACK.get_or_init(ComposeStack::start);
        let client = Client::new();
        wait_for_compose_api(&client).await;

        Self {
            runtime: Some(TestRuntime::Compose(compose_stack)),
            client,
            base_url: COMPOSE_API_BASE_URL.to_string(),
            dns_secondary_ports: SECONDARY_PORTS.to_vec(),
            namespace: test_namespace(),
        }
    }

    pub(crate) fn zone_name(&self, base: &str) -> String {
        format!("{}.{}", self.namespace, base.trim_end_matches('.'))
    }

    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let should_verify_dns = method != Method::GET;
        let mut previous_dns_key = self.previous_dns_key(&method, path).await;
        let updated_zone_name = (method == Method::PUT)
            .then(|| path.strip_prefix("/zones/"))
            .flatten();
        let response = self.send_request(method, path, body).await;

        if let Some(previous_zone_name) = updated_zone_name
            && response.0.is_success()
            && response.1["zone"]["name"].as_str() == Some(previous_zone_name)
        {
            previous_dns_key = None;
        }

        if should_verify_dns && response.0.is_success() {
            self.assert_dns_matches_api(previous_dns_key).await;
        }

        response
    }

    async fn send_request(
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
        let zone_name = self.zone_name("example.com");
        let request = json!({
            "name": zone_name,
            "primary_ns": format!("ns1.{zone_name}"),
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

    pub(crate) async fn run_cli(&self, args: &[&str]) -> std::process::Output {
        let previous_dns_key = match args {
            ["delete", "record", record_id, ..] => {
                self.previous_dns_key(&Method::DELETE, &format!("/records/{record_id}"))
                    .await
            }
            ["delete", "zone", zone_name, ..] => Some((zone_name.to_string(), 6)),
            _ => None,
        };
        let mut command = match self.runtime.as_ref().expect("test runtime is missing") {
            TestRuntime::Local { .. } => Command::new(env!("CARGO_BIN_EXE_bindizr")),
            TestRuntime::Compose(stack) => stack.cli_command(),
        };

        let output = command
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("failed to run bindizr CLI");

        if output.status.success()
            && matches!(args.first().copied(), Some("create" | "delete" | "notify"))
        {
            self.assert_dns_matches_api(previous_dns_key).await;
        }

        output
    }

    pub(crate) async fn run_cli_success(&self, args: &[&str]) -> String {
        let output = self.run_cli(args).await;
        assert_cli_success(args, &output);
        String::from_utf8(output.stdout).expect("CLI stdout was not UTF-8")
    }

    async fn previous_dns_key(&self, method: &Method, path: &str) -> Option<(String, u16)> {
        if !matches!(*method, Method::PUT | Method::DELETE) {
            return None;
        }

        if path.starts_with("/records/") {
            let (status, body) = self.send_request(Method::GET, path, None).await;
            return status
                .is_success()
                .then(|| dns_key_from_record(&body["record"]));
        }

        if let Some(zone_name) = path.strip_prefix("/zones/") {
            return Some((zone_name.to_string(), 6));
        }

        None
    }

    async fn assert_dns_matches_api(&self, previous_dns_key: Option<(String, u16)>) {
        if self.dns_secondary_ports.is_empty() {
            return;
        }

        let (status, body) = self
            .send_request(
                Method::GET,
                &format!("/records?search={}&limit=10000", self.namespace),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "failed to list records for DNS verification"
        );

        let mut expected = HashMap::<(String, u16), Vec<Value>>::new();
        for record in body["items"]
            .as_array()
            .expect("record list response did not contain items")
        {
            let name = record["name"]
                .as_str()
                .expect("record did not contain a name")
                .to_string();
            let record_type = record["record_type"]
                .as_str()
                .and_then(dns_record_type)
                .expect("record contained an unsupported DNS type");
            expected
                .entry((name, record_type))
                .or_default()
                .push(dns_expected_value(record, record_type));
        }

        for ((name, record_type), values) in &expected {
            for port in &self.dns_secondary_ports {
                wait_for_dns_records(*port, name, *record_type, values).await;
            }
        }

        if let Some((name, record_type)) = previous_dns_key
            && !expected.contains_key(&(name.clone(), record_type))
        {
            for port in &self.dns_secondary_ports {
                wait_for_dns_records(*port, &name, record_type, &[]).await;
            }
        }
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        match self.runtime.take() {
            Some(TestRuntime::Local {
                temp_dir,
                mut child,
            }) => {
                let _ = child.kill();
                let _ = child.wait();
                drop(temp_dir);
            }
            Some(TestRuntime::Compose(_)) => {}
            None => {}
        }
    }
}

struct ComposeStack {
    project_name: String,
    compose_dir: PathBuf,
}

impl ComposeStack {
    fn start() -> Self {
        let stack = Self {
            project_name: COMPOSE_PROJECT_NAME.to_string(),
            compose_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        };

        if compose_services_are_reachable() {
            eprintln!("Reusing the running Docker Compose DNS E2E stack...");
        } else {
            eprintln!("Starting Docker Compose DNS E2E stack...");
            stack.run_compose(&["up", "-d", "--build", "bindizr", "bind9-1", "bind9-2"]);
            stack.run_compose(&["ps"]);
        }

        stack
    }

    fn cli_command(&self) -> Command {
        let mut command = Command::new("docker");
        command
            .arg("compose")
            .arg("-p")
            .arg(&self.project_name)
            .arg("-f")
            .arg(COMPOSE_FILE)
            .args(["exec", "-T", "bindizr", "bindizr"])
            .current_dir(&self.compose_dir);
        command
    }

    fn run_compose(&self, args: &[&str]) {
        eprintln!(
            "Running: docker compose -p {} -f {COMPOSE_FILE} {}",
            self.project_name,
            args.join(" ")
        );

        let mut child = Command::new("docker")
            .arg("compose")
            .arg("-p")
            .arg(&self.project_name)
            .arg("-f")
            .arg(COMPOSE_FILE)
            .args(args)
            .current_dir(&self.compose_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to run docker compose");

        let started_at = Instant::now();
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .expect("failed to check docker compose status")
            {
                break status;
            }

            if started_at.elapsed() > COMPOSE_COMMAND_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "docker compose {} timed out after {} seconds",
                    args.join(" "),
                    COMPOSE_COMMAND_TIMEOUT.as_secs()
                );
            }

            std::thread::sleep(Duration::from_secs(1));
        };

        assert!(
            status.success(),
            "docker compose {} failed with status {status}",
            args.join(" ")
        );
    }
}

fn compose_services_are_reachable() -> bool {
    [8000, SECONDARY_PORTS[0], SECONDARY_PORTS[1]]
        .into_iter()
        .all(|port| {
            TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_millis(250),
            )
            .is_ok()
        })
}

fn test_namespace() -> String {
    let run_id = RUN_ID.get_or_init(|| {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is before the Unix epoch");
        format!("e2e-{}-{}", elapsed.as_millis(), std::process::id())
    });
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{run_id}-{sequence}")
}

fn dns_verification_enabled() -> bool {
    match env::var(DNS_VERIFICATION_ENV) {
        Err(env::VarError::NotPresent) => false,
        Err(error) => panic!("failed to read {DNS_VERIFICATION_ENV}: {error}"),
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => panic!("invalid {DNS_VERIFICATION_ENV} value '{value}'; use true/false or 1/0"),
        },
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

        if let Ok(response) = client.get(base_url).send().await
            && response.status() == StatusCode::OK
        {
            return;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("bindizr API did not become ready");
}

async fn wait_for_compose_api(client: &Client) {
    eprintln!("Waiting for bindizr API at {COMPOSE_API_BASE_URL}...");
    for attempt in 1..=120 {
        if let Ok(response) = client.get(COMPOSE_API_BASE_URL).send().await
            && response.status() == StatusCode::OK
        {
            eprintln!("bindizr API is ready.");
            return;
        }

        if attempt % 10 == 0 {
            eprintln!("Still waiting for bindizr API... {attempt}s elapsed");
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!("bindizr API did not become ready at {COMPOSE_API_BASE_URL}");
}
