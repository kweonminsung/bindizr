use std::{
    net::{Ipv4Addr, UdpSocket},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

const COMPOSE_FILE: &str = "docker-compose.yml";
const API_BASE_URL: &str = "http://127.0.0.1:8000";
const SECONDARY_ONE_PORT: u16 = 1053;
const SECONDARY_TWO_PORT: u16 = 1054;
const COMPOSE_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);

#[tokio::test]
#[ignore = "requires docker compose and bind9"]
#[serial_test::serial(bindizr_dns_e2e)]
async fn bind9_secondaries_serve_records_created_through_api() {
    let _stack = ComposeStack::start();
    let client = Client::new();

    wait_for_api(&client).await;

    create_zone(&client, "dns-e2e.example").await;
    create_a_record(&client, "api", "dns-e2e.example", "192.0.2.55").await;

    wait_for_a_record(SECONDARY_ONE_PORT, "api.dns-e2e.example", "192.0.2.55").await;
    wait_for_a_record(SECONDARY_TWO_PORT, "api.dns-e2e.example", "192.0.2.55").await;
}

struct ComposeStack {
    project_name: String,
    compose_dir: PathBuf,
}

impl ComposeStack {
    fn start() -> Self {
        let project_name = format!("bindizr-e2e-dns-{}", std::process::id());
        let stack = Self {
            project_name,
            compose_dir: compose_dir(),
        };

        eprintln!("Starting Docker Compose DNS E2E stack...");
        stack.run_compose(&["up", "-d", "--build", "bindizr", "bind9-1", "bind9-2"]);
        stack.run_compose(&["ps"]);

        stack
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

impl Drop for ComposeStack {
    fn drop(&mut self) {
        // Best-effort cleanup keeps volumes and fixed test ports from leaking after failures.
        let _ = Command::new("docker")
            .arg("compose")
            .arg("-p")
            .arg(&self.project_name)
            .arg("-f")
            .arg(COMPOSE_FILE)
            .args(["down", "-v", "--remove-orphans"])
            .current_dir(&self.compose_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
    }
}

fn compose_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

async fn wait_for_api(client: &Client) {
    eprintln!("Waiting for bindizr API at {API_BASE_URL}...");
    for attempt in 1..=120 {
        if let Ok(response) = client.get(API_BASE_URL).send().await
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

    panic!("bindizr API did not become ready at {API_BASE_URL}");
}

async fn create_zone(client: &Client, zone_name: &str) {
    let request = json!({
        "name": zone_name,
        "primary_ns": format!("ns1.{zone_name}"),
        "admin_email": format!("hostmaster@{zone_name}"),
        "ttl": 3600,
        "serial": 2026010101_i64,
        "refresh": 7200,
        "retry": 3600,
        "expire": 604800,
        "minimum_ttl": 86400
    });

    let body = post_json(client, "/zones", request, StatusCode::CREATED).await;
    assert_eq!(body["zone"]["name"], zone_name);
}

async fn create_a_record(client: &Client, name: &str, zone_name: &str, value: &str) {
    let request = json!({
        "name": name,
        "record_type": "A",
        "value": value,
        "ttl": 300,
        "zone_name": zone_name
    });

    let body = post_json(client, "/records", request, StatusCode::CREATED).await;
    assert_eq!(body["record"]["name"], format!("{name}.{zone_name}."));
    assert_eq!(body["record"]["value"], value);
}

async fn post_json(
    client: &Client,
    path: &str,
    request: Value,
    expected_status: StatusCode,
) -> Value {
    let response = client
        .post(format!("{API_BASE_URL}{path}"))
        .json(&request)
        .send()
        .await
        .expect("failed to send API request");
    let status = response.status();
    let body = response
        .json::<Value>()
        .await
        .expect("failed to parse API response as JSON");

    assert_eq!(status, expected_status, "unexpected response body: {body}");

    body
}

async fn wait_for_a_record(port: u16, name: &str, expected_addr: &str) {
    eprintln!("Waiting for {name} A {expected_addr} on 127.0.0.1:{port}...");
    for attempt in 1..=120 {
        if let Ok(addrs) = query_a_record(port, name)
            && addrs.iter().any(|addr| addr.to_string() == expected_addr)
        {
            eprintln!("{name} resolved through 127.0.0.1:{port}.");
            return;
        }

        if attempt % 10 == 0 {
            eprintln!("Still waiting for DNS answer on 127.0.0.1:{port}... {attempt}s elapsed");
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!("A record {name} did not resolve to {expected_addr} on 127.0.0.1:{port}");
}

fn query_a_record(port: u16, name: &str) -> Result<Vec<Ipv4Addr>, String> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;

    let query_id = (std::process::id() as u16).wrapping_add(port);
    let query = build_a_query(query_id, name)?;
    socket
        .send_to(&query, ("127.0.0.1", port))
        .map_err(|e| e.to_string())?;

    let mut response = [0_u8; 1500];
    let (len, _) = socket.recv_from(&mut response).map_err(|e| e.to_string())?;

    parse_a_response(query_id, &response[..len])
}

fn build_a_query(query_id: u16, name: &str) -> Result<Vec<u8>, String> {
    let mut query = Vec::new();
    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&0x0000_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_name(name, &mut query)?;
    query.extend_from_slice(&1_u16.to_be_bytes());
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

fn parse_a_response(query_id: u16, response: &[u8]) -> Result<Vec<Ipv4Addr>, String> {
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
    if flags & 0x000f != 0 {
        return Err(format!("DNS response returned rcode {}", flags & 0x000f));
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

    let mut addrs = Vec::new();
    for _ in 0..answer_count {
        offset = skip_dns_name(response, offset)?;
        if offset + 10 > response.len() {
            return Err("DNS answer header extends beyond response".to_string());
        }

        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let record_class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlen > response.len() {
            return Err("DNS answer rdata extends beyond response".to_string());
        }

        if record_type == 1 && record_class == 1 && rdlen == 4 {
            addrs.push(Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            ));
        }

        offset += rdlen;
    }

    Ok(addrs)
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
