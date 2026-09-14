use std::{
    collections::HashMap,
    env,
    io::Write,
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;

mod assertions;
mod compose;
mod external_dns;
mod local;

use compose::ComposeStack;
pub(crate) use external_dns::ExternalDnsAdapter;
pub(crate) mod dns;
pub(crate) mod nsupdate;

pub(crate) use assertions::{assert_cli_failure_contains, assert_cli_success};
pub(crate) use dns::{
    FakeParent, ServedDs, TransferOutcome, axfr, probe_zone_soa, wait_for_any_dns_record,
};
use dns::{dns_expected_value, dns_key_from_record, dns_record_type, wait_for_dns_records};

const DNS_VERIFICATION_ENV: &str = "BINDIZR_E2E_VERIFY_DNS";
static TEST_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
static RUN_ID: OnceLock<String> = OnceLock::new();

pub(crate) struct TestApp {
    runtime: TestRuntime,
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
    pub(crate) require_authentication: bool,
    pub(crate) external_dns_enabled: bool,
    pub(crate) nsupdate_allow_unsigned: bool,
    pub(crate) openapi_enabled: bool,
    /// Also the zone-transfer ACL; NOTIFY stays off in tests.
    pub(crate) secondary_addrs: String,
    /// Serve the API over HTTPS with a certificate generated for this run.
    pub(crate) tls: bool,
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
    /// grant zones with `token grant`.
    pub(crate) async fn create_scoped_api_token(&self) -> (String, String) {
        let name = format!("{}-scoped", self.namespace);
        self.create_token_with(&["token", "create", "--name", &name])
            .await
    }

    async fn create_token_with(&self, args: &[&str]) -> (String, String) {
        let args = [args, &["--output", "json"]].concat();
        let stdout = self.run_cli_success(&args).await;
        let created: Value =
            serde_json::from_str(&stdout).expect("token create did not print JSON");
        let field = |value: &Value, what: &str| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("token create output did not contain the {what}"))
                .to_string()
        };
        (
            field(&created["token"]["name"], "name"),
            field(&created["secret"], "secret"),
        )
    }

    pub(crate) fn zone_name(&self, base: &str) -> String {
        format!("{}.{}", self.namespace, base.trim_end_matches('.'))
    }

    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The config file the local daemon was started from, for tests that
    /// rewrite it and reload.
    pub(crate) fn config_path(&self) -> std::path::PathBuf {
        match &self.runtime {
            TestRuntime::Local { temp_dir, .. } => temp_dir.path().join("bindizr.conf.toml"),
            _ => panic!("only the local runtime owns its config file"),
        }
    }

    pub(crate) fn has_dns_secondaries(&self) -> bool {
        !self.dns_secondary_ports.is_empty()
    }

    /// Ports of the compose stack's BIND9 secondaries; empty in local mode.
    pub(crate) fn dns_secondary_ports(&self) -> &[u16] {
        &self.dns_secondary_ports
    }

    /// One API request; in compose mode every mutating call also asserts the
    /// DNS secondaries match the API.
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
        let mut command = match &self.runtime {
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
                &format!("/records?search={}&limit=1000", self.namespace),
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
        if let TestRuntime::Local { child, .. } = &mut self.runtime {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
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
