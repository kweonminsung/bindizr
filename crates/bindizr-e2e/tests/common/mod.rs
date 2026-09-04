use std::{
    collections::HashMap,
    env, fs,
    io::{Read, Write},
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
pub(crate) mod nsupdate;

pub(crate) use assertions::{assert_cli_failure_contains, assert_cli_success};
pub(crate) use dns::wait_for_any_dns_record;
use dns::{dns_expected_value, dns_key_from_record, dns_record_type, wait_for_dns_records};

const COMPOSE_FILE: &str = "docker-compose.yml";
const ARM_COMPOSE_FILE: &str = "docker-compose.arm.yml";
const COMPOSE_PROJECT_NAME: &str = "bindizr-e2e-dns";
const COMPOSE_API_BASE_URL: &str = "http://127.0.0.1:8000";
const DNS_VERIFICATION_ENV: &str = "BINDIZR_E2E_VERIFY_DNS";
const ARM_STACK_ENV: &str = "BINDIZR_E2E_ARM";
const SECONDARY_PORTS: [u16; 2] = [1053, 1054];
const COMPOSE_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
static COMPOSE_STACK: OnceLock<ComposeStack> = OnceLock::new();
static TEST_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
static RUN_ID: OnceLock<String> = OnceLock::new();

pub(crate) struct TestApp {
    runtime: Option<TestRuntime>,
    client: Client,
    base_url: String,
    dns_port: Option<u16>,
    dns_secondary_ports: Vec<u16>,
    namespace: String,
    auth_token: Option<String>,
}

/// Config knobs for a locally spawned bindizr; `start()` uses the defaults.
#[derive(Default)]
pub(crate) struct TestAppOptions {
    pub require_authentication: bool,
    pub external_dns_enabled: bool,
    pub nsupdate_allow_unsigned: bool,
    pub openapi_enabled: bool,
    /// Also the zone-transfer ACL; NOTIFY stays off in tests.
    pub secondary_addrs: String,
}

enum TestRuntime {
    Local { temp_dir: TempDir, child: Child },
    Compose(&'static ComposeStack),
}

impl TestApp {
    pub(crate) async fn start() -> Self {
        if env_flag(DNS_VERIFICATION_ENV) {
            Self::start_compose().await
        } else {
            Self::start_with_options(TestAppOptions::default()).await
        }
    }

    /// A locally spawned daemon with the default config, even in compose
    /// mode — for tests bound to this host's filesystem or default config.
    pub(crate) async fn start_local() -> Self {
        Self::start_with_options(TestAppOptions::default()).await
    }

    /// Start with non-default config; always the local runtime, because the
    /// compose stack's config is fixed.
    pub(crate) async fn start_with_options(options: TestAppOptions) -> Self {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("bindizr.sqlite");
        fs::File::create(&db_path).expect("failed to create sqlite file");
        let config_path = temp_dir.path().join("bindizr.conf.toml");
        let client = Client::new();

        // A reserved port is released before the daemon binds it, so another
        // socket can take it in between; fresh ports and a retry cover that.
        let mut failures = Vec::new();
        for _ in 0..3 {
            let api_port = reserve_tcp_port();
            let dns_port = reserve_dns_port();
            write_config(&config_path, api_port, dns_port, &db_path, &options);

            let mut child = Command::new(env!("CARGO_BIN_EXE_bindizr-e2e-server"))
                .arg("start")
                .arg("-c")
                .arg(&config_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to start bindizr binary");

            let base_url = format!("http://127.0.0.1:{api_port}");
            match wait_for_api(&client, &base_url, &mut child).await {
                Ok(()) => {
                    return Self {
                        runtime: Some(TestRuntime::Local { temp_dir, child }),
                        client,
                        base_url,
                        dns_port: Some(dns_port),
                        dns_secondary_ports: Vec::new(),
                        namespace: test_namespace(),
                        auth_token: None,
                    };
                }
                Err(failure) => failures.push(failure),
            }
        }

        panic!(
            "bindizr did not start:
{}",
            failures.join(
                "
---
"
            )
        );
    }

    async fn start_compose() -> Self {
        let compose_stack = COMPOSE_STACK.get_or_init(ComposeStack::start);
        let client = Client::new();
        wait_for_compose_api(&client).await;

        Self {
            runtime: Some(TestRuntime::Compose(compose_stack)),
            client,
            base_url: COMPOSE_API_BASE_URL.to_string(),
            dns_port: None,
            dns_secondary_ports: SECONDARY_PORTS.to_vec(),
            namespace: test_namespace(),
            auth_token: None,
        }
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Port bindizr's own DNS listener is bound to; only the local runtime
    /// picks one, the compose stack fixes it.
    pub(crate) fn dns_port(&self) -> u16 {
        self.dns_port.expect("local runtime binds a DNS port")
    }

    /// Bearer token attached to every subsequent HTTP request.
    pub(crate) fn set_auth_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    /// Create a global API token over the daemon socket (which needs no HTTP
    /// auth) and return its `(name, plaintext token)`.
    pub(crate) async fn create_api_token(&self) -> (String, String) {
        let name = format!("{}-global", self.namespace);
        self.create_token_with(&["token", "create", "--name", &name, "--global"])
            .await
    }

    /// Create a scoped API token and return its `(name, plaintext token)`;
    /// grant zones with `zone token-policy add`.
    pub(crate) async fn create_scoped_api_token(&self) -> (String, String) {
        let name = format!("{}-scoped", self.namespace);
        self.create_token_with(&["token", "create", "--name", &name])
            .await
    }

    async fn create_token_with(&self, args: &[&str]) -> (String, String) {
        let stdout = self.run_cli_success(args).await;
        let field = |prefix: &str| {
            stdout
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .unwrap_or_else(|| panic!("token create output did not contain '{prefix}'"))
                .trim()
                .to_string()
        };
        (field("Name: "), field("Token: "))
    }

    pub(crate) fn zone_name(&self, base: &str) -> String {
        format!("{}.{}", self.namespace, base.trim_end_matches('.'))
    }

    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) fn has_dns_secondaries(&self) -> bool {
        !self.dns_secondary_ports.is_empty()
    }

    /// Ports of the compose stack's BIND9 secondaries; empty in local mode.
    pub(crate) fn dns_secondary_ports(&self) -> &[u16] {
        &self.dns_secondary_ports
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
        if let Some(token) = &self.auth_token {
            request = request.bearer_auth(token);
        }
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

    pub(crate) async fn list_records(&self, zone_name: &str) -> Vec<Value> {
        let (status, body) = self
            .request(
                Method::GET,
                &format!("/zones/{zone_name}?records=true"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        body["records"]
            .as_array()
            .expect("zone detail carries a records array")
            .clone()
    }

    pub(crate) async fn zone_serial(&self, zone_name: &str) -> i64 {
        let (status, body) = self
            .request(Method::GET, &format!("/zones/{zone_name}"), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        body["zone"]["serial"]
            .as_i64()
            .expect("zone carries a serial")
    }

    pub(crate) async fn create_test_zone(&self) -> Value {
        let zone_name = self.zone_name("example.com");
        let request = json!({
            "name": zone_name,
            "mname": format!("ns1.{zone_name}"),
            "rname": "admin@example.com",
            "default_ttl": 3600,
            "serial": 10,
            "refresh": 7200,
            "retry": 3600,
            "expire": 604800,
            "minimum_ttl": 86400
        });
        let (status, body) = self.request(Method::POST, "/zones", Some(request)).await;
        assert_eq!(status, StatusCode::CREATED);
        body["zone"].clone()
    }

    /// CLI-side twin of `create_test_zone`: create a zone via `zone create` and
    /// return the CLI output.
    pub(crate) async fn create_zone_cli(&self, zone_name: &str, default_ttl: &str) -> String {
        let mname = format!("ns1.{zone_name}");
        let rname = format!("hostmaster@{zone_name}");
        self.run_cli_success(&[
            "zone",
            "create",
            "--name",
            zone_name,
            "--mname",
            &mname,
            "--rname",
            &rname,
            "--default-ttl",
            default_ttl,
        ])
        .await
    }

    pub(crate) async fn run_cli(&self, args: &[&str]) -> std::process::Output {
        self.run_cli_with_input(args, None).await
    }

    /// Run the CLI, optionally piping `input` to its stdin (for `-` file args).
    async fn run_cli_with_input(&self, args: &[&str], input: Option<&str>) -> std::process::Output {
        let previous_dns_key = match args {
            ["record", "delete", record_id, ..] => {
                self.previous_dns_key(&Method::DELETE, &format!("/records/{record_id}"))
                    .await
            }
            ["zone", "delete", zone_name, ..] => Some((zone_name.to_string(), 6)),
            _ => None,
        };
        let mut command = match self.runtime.as_ref().expect("test runtime is missing") {
            TestRuntime::Local { .. } => Command::new(env!("CARGO_BIN_EXE_bindizr-e2e-server")),
            TestRuntime::Compose(stack) => stack.cli_command(),
        };
        command.args(args);

        let output = match input {
            Some(input) => {
                let mut child = command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("failed to start bindizr CLI");
                child
                    .stdin
                    .take()
                    .expect("missing CLI stdin")
                    .write_all(input.as_bytes())
                    .expect("failed to write to CLI stdin");
                child.wait_with_output().expect("failed to run bindizr CLI")
            }
            None => command
                .stdin(Stdio::null())
                .output()
                .expect("failed to run bindizr CLI"),
        };

        if output.status.success()
            && matches!(
                args,
                [
                    "zone" | "record",
                    "create" | "bulk-create" | "delete" | "import" | "notify" | "rollback",
                    ..
                ]
            )
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

    pub(crate) async fn run_cli_success_with_input(&self, args: &[&str], input: &str) -> String {
        let output = self.run_cli_with_input(args, Some(input)).await;
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
        let mut command = self.compose_command();
        command.args(["exec", "-T", "bindizr", "bindizr"]);
        command
    }

    fn compose_command(&self) -> Command {
        let mut command = Command::new("docker");
        command.arg("compose").arg("-p").arg(&self.project_name);
        for file in compose_files() {
            command.arg("-f").arg(file);
        }
        command.current_dir(&self.compose_dir);
        command
    }

    fn run_compose(&self, args: &[&str]) {
        eprintln!(
            "Running: docker compose -p {} -f {} {}",
            self.project_name,
            compose_files().join(" -f "),
            args.join(" ")
        );

        let mut command = self.compose_command();
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = command.spawn().expect("failed to run docker compose");

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

/// The ARM override swaps the amd64-only ISC bind9 image for a multi-arch one.
fn compose_files() -> Vec<&'static str> {
    if env_flag(ARM_STACK_ENV) {
        vec![COMPOSE_FILE, ARM_COMPOSE_FILE]
    } else {
        vec![COMPOSE_FILE]
    }
}

fn env_flag(name: &str) -> bool {
    match env::var(name) {
        Err(env::VarError::NotPresent) => false,
        Err(error) => panic!("failed to read {name}: {error}"),
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => panic!("invalid {name} value '{value}'; use true/false or 1/0"),
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

fn write_config(
    config_path: &Path,
    api_port: u16,
    dns_port: u16,
    db_path: &Path,
    options: &TestAppOptions,
) {
    let config = format!(
        r#"
[api]
listen_addr = "127.0.0.1"
listen_port = {api_port}
require_authentication = {require_authentication}
external_dns_enabled = {external_dns_enabled}
openapi_enabled = {openapi_enabled}

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
secondary_addrs = "{secondary_addrs}"
notify_after_update = false
notify_on_startup = false
notify_retries = 0
notify_timeout_secs = 1
nsupdate_allow_unsigned = {nsupdate_allow_unsigned}

[logging]
log_level = "error"
"#,
        db_path.display(),
        require_authentication = options.require_authentication,
        external_dns_enabled = options.external_dns_enabled,
        nsupdate_allow_unsigned = options.nsupdate_allow_unsigned,
        openapi_enabled = options.openapi_enabled,
        secondary_addrs = options.secondary_addrs,
    );

    fs::write(config_path, config).expect("failed to write bindizr config");
}

/// Poll `/health` until the daemon answers; a failure carries the daemon's
/// stderr, the only place a daemon that dies before listening says why.
async fn wait_for_api(client: &Client, base_url: &str, child: &mut Child) -> Result<(), String> {
    // /health sits outside the auth layer, so readiness ignores
    // require_authentication.
    let health_url = format!("{base_url}/health");
    let mut attempts = 0;
    let failure = loop {
        if let Some(status) = child.try_wait().expect("failed to check child status") {
            break format!("bindizr exited before API was ready: {status}");
        }

        if let Ok(response) = client.get(&health_url).send().await
            && response.status() == StatusCode::OK
        {
            return Ok(());
        }

        attempts += 1;
        if attempts == 100 {
            let _ = child.kill();
            let _ = child.wait();
            break "bindizr API did not become ready".to_string();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    Err(format!("{failure}\n{stderr}"))
}

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
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
