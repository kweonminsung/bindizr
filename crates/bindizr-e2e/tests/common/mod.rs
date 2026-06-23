use std::{
    collections::HashMap,
    env, fs,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
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

pub(crate) mod notify;

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

fn dns_expected_value(record: &Value, record_type: u16) -> Value {
    let value = record["value"].clone();
    if !matches!(record_type, 15 | 33) {
        return value;
    }

    let Some(target) = value.as_str() else {
        return value;
    };

    let fields = target.split_whitespace().collect::<Vec<_>>();
    let expects_priority_fallback = match record_type {
        15 => fields.len() == 1,
        33 => fields.len() == 3,
        _ => false,
    };
    if !expects_priority_fallback {
        return value;
    }

    let priority = record["priority"].as_u64().unwrap_or(10);
    json!(format!("{priority} {target}"))
}

fn dns_key_from_record(record: &Value) -> (String, u16) {
    let name = record["name"]
        .as_str()
        .expect("record did not contain a name")
        .to_string();
    let record_type = record["record_type"]
        .as_str()
        .and_then(dns_record_type)
        .expect("record contained an unsupported DNS type");
    (name, record_type)
}

pub(crate) fn assert_cli_success(args: &[&str], output: &std::process::Output) {
    assert!(
        output.status.success(),
        "bindizr {} failed\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn assert_cli_failure_contains(
    args: &[&str],
    output: &std::process::Output,
    expected_error: &str,
) {
    assert!(
        !output.status.success(),
        "expected bindizr {} to fail, but it succeeded.\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(expected_error),
        "bindizr {} response did not contain '{expected_error}': {combined}",
        args.join(" ")
    );
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

        if let Ok(response) = client.get(base_url).send().await {
            if response.status() == StatusCode::OK {
                return;
            }
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

fn dns_record_type(record_type: &str) -> Option<u16> {
    match record_type {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        _ => None,
    }
}

async fn wait_for_dns_records(port: u16, name: &str, record_type: u16, expected: &[Value]) {
    let expected_count = expected.len();
    eprintln!(
        "Waiting for {expected_count} type {record_type} record(s) for {name} on 127.0.0.1:{port}..."
    );
    for attempt in 1..=120 {
        if let Ok(answers) = query_dns_record(port, name, record_type)
            && answers
                .iter()
                .filter(|answer| answer.record_type == record_type)
                .count()
                == expected_count
            && dns_values_match(record_type, expected, &answers)
        {
            eprintln!("{name} type {record_type} propagated through 127.0.0.1:{port}.");
            return;
        }

        if attempt % 10 == 0 {
            eprintln!(
                "Still waiting for DNS type {record_type} on 127.0.0.1:{port}... {attempt}s elapsed"
            );
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!(
        "{expected_count} type {record_type} record(s) for {name} did not propagate to 127.0.0.1:{port}"
    );
}

#[derive(Debug)]
struct DnsAnswer {
    record_type: u16,
    value: Option<Value>,
}

fn dns_values_match(record_type: u16, expected: &[Value], answers: &[DnsAnswer]) -> bool {
    if record_type == 6 {
        return true;
    }
    let normalize = |value: &Value| {
        let value = value.to_string();
        if matches!(record_type, 2 | 5 | 12 | 15 | 33) {
            value.to_ascii_lowercase()
        } else {
            value
        }
    };
    let mut expected = expected.iter().map(normalize).collect::<Vec<_>>();
    let mut actual = answers
        .iter()
        .filter(|answer| answer.record_type == record_type)
        .filter_map(|answer| answer.value.as_ref().map(normalize))
        .collect::<Vec<_>>();
    expected.sort();
    actual.sort();
    expected == actual
}

fn query_dns_record(port: u16, name: &str, record_type: u16) -> Result<Vec<DnsAnswer>, String> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;

    let query_id = (std::process::id() as u16).wrapping_add(port);
    let query = build_dns_query(query_id, name, record_type)?;
    socket
        .send_to(&query, ("127.0.0.1", port))
        .map_err(|e| e.to_string())?;

    let mut response = [0_u8; 1500];
    let (len, _) = socket.recv_from(&mut response).map_err(|e| e.to_string())?;

    parse_dns_response(query_id, &response[..len])
}

fn build_dns_query(query_id: u16, name: &str, record_type: u16) -> Result<Vec<u8>, String> {
    let mut query = Vec::new();
    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&0x0000_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_name(name, &mut query)?;
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());

    Ok(query)
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> Result<(), String> {
    for label in name.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len()).map_err(|_| format!("label too long: {label}"))?;
        if len > 63 {
            return Err(format!("label too long: {label}"));
        }

        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }

    out.push(0);
    Ok(())
}

fn parse_dns_response(query_id: u16, response: &[u8]) -> Result<Vec<DnsAnswer>, String> {
    if response.len() < 12 {
        return Err("DNS response header is too short".to_string());
    }

    if u16::from_be_bytes([response[0], response[1]]) != query_id {
        return Err("DNS response query id mismatch".to_string());
    }

    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err("DNS response is not marked as a response".to_string());
    }
    let response_code = flags & 0x000f;
    if response_code != 0 {
        return Ok(Vec::new());
    }

    let question_count = u16::from_be_bytes([response[4], response[5]]) as usize;
    let answer_count = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut offset = 12;

    for _ in 0..question_count {
        offset = skip_dns_name(response, offset)?;
        offset = offset
            .checked_add(4)
            .ok_or_else(|| "DNS question offset overflow".to_string())?;
        if offset > response.len() {
            return Err("DNS question extends beyond response".to_string());
        }
    }

    let mut answers = Vec::new();
    for _ in 0..answer_count {
        offset = skip_dns_name(response, offset)?;
        if offset + 10 > response.len() {
            return Err("DNS answer header extends beyond response".to_string());
        }

        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlen > response.len() {
            return Err("DNS answer rdata extends beyond response".to_string());
        }

        answers.push(DnsAnswer {
            record_type,
            value: decode_dns_value(response, record_type, offset, rdlen)?,
        });
        offset += rdlen;
    }

    Ok(answers)
}

fn decode_dns_value(
    response: &[u8],
    record_type: u16,
    offset: usize,
    rdlen: usize,
) -> Result<Option<Value>, String> {
    let end = offset + rdlen;
    let value = match record_type {
        1 if rdlen == 4 => Value::String(
            Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            )
            .to_string(),
        ),
        28 if rdlen == 16 => {
            let bytes: [u8; 16] = response[offset..end]
                .try_into()
                .map_err(|_| "invalid AAAA")?;
            Value::String(Ipv6Addr::from(bytes).to_string())
        }
        2 | 5 | 12 => Value::String(decode_dns_name(response, offset)?),
        15 => {
            if rdlen < 2 {
                return Err("invalid MX rdlen".to_string());
            }
            Value::String(format!(
                "{} {}",
                u16::from_be_bytes([response[offset], response[offset + 1]]),
                decode_dns_name(response, offset + 2)?
            ))
        }
        33 => {
            if rdlen < 6 {
                return Err("invalid SRV rdlen".to_string());
            }
            Value::String(format!(
                "{} {} {} {}",
                u16::from_be_bytes([response[offset], response[offset + 1]]),
                u16::from_be_bytes([response[offset + 2], response[offset + 3]]),
                u16::from_be_bytes([response[offset + 4], response[offset + 5]]),
                decode_dns_name(response, offset + 6)?
            ))
        }
        16 => {
            let mut position = offset;
            let mut segments = Vec::new();
            while position < end {
                let len = response[position] as usize;
                position += 1;
                if position + len > end {
                    return Err("invalid TXT rdata".to_string());
                }
                segments.push(String::from_utf8_lossy(&response[position..position + len]).into());
                position += len;
            }
            if segments.len() == 1 {
                Value::String(segments.remove(0))
            } else {
                serde_json::to_value(segments).map_err(|error| error.to_string())?
            }
        }
        6 => return Ok(None),
        _ => return Err(format!("unsupported DNS answer type {record_type}")),
    };
    Ok(Some(value))
}

fn decode_dns_name(response: &[u8], mut offset: usize) -> Result<String, String> {
    let mut labels = Vec::<String>::new();
    for _ in 0..128 {
        let len = *response.get(offset).ok_or("DNS name out of bounds")?;
        if len == 0 {
            return Ok(format!("{}.", labels.join(".")));
        }
        if len & 0xc0 == 0xc0 {
            let next = *response
                .get(offset + 1)
                .ok_or("DNS pointer out of bounds")?;
            offset = (((len & 0x3f) as usize) << 8) | next as usize;
            continue;
        }
        let start = offset + 1;
        let end = start + len as usize;
        labels.push(
            String::from_utf8_lossy(response.get(start..end).ok_or("DNS label out of bounds")?)
                .into(),
        );
        offset = end;
    }
    Err("DNS compression pointer loop".to_string())
}

fn skip_dns_name(response: &[u8], mut offset: usize) -> Result<usize, String> {
    loop {
        let len = *response
            .get(offset)
            .ok_or_else(|| "DNS name extends beyond response".to_string())?;

        if len & 0xc0 == 0xc0 {
            if offset + 1 >= response.len() {
                return Err("DNS compression pointer extends beyond response".to_string());
            }
            return Ok(offset + 2);
        }

        if len == 0 {
            return Ok(offset + 1);
        }

        if len & 0xc0 != 0 {
            return Err("DNS name has unsupported label format".to_string());
        }

        offset = offset
            .checked_add(1 + len as usize)
            .ok_or_else(|| "DNS name offset overflow".to_string())?;
    }
}
