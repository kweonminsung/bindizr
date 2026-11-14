//! Lifecycle of the shared BIND9 Compose stack.

use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tokio::time;

use crate::common;
use crate::common::{TestApp, TestRuntime};

/// The compose file that defines the DNS stack.
const COMPOSE_FILE: &str = "docker-compose.yml";

/// The override compose file for ARM hosts.
const ARM_COMPOSE_FILE: &str = "docker-compose.arm.yml";

/// The Compose project name the stack runs under.
const COMPOSE_PROJECT_NAME: &str = "bindizr-e2e-dns";

/// The compose bindizr's HTTP API as the host reaches it.
const COMPOSE_API_BASE_URL: &str = "http://127.0.0.1:8000";

/// The switch that adds the ARM override compose file.
const ARM_STACK_ENV: &str = "BINDIZR_E2E_ARM";

/// The host ports of the BIND9 secondaries' DNS listeners.
const SECONDARY_PORTS: [u16; 2] = [1053, 1054];

/// The BIND9 services of the compose file, by the names the daemon reaches them at.
const COMPOSE_SECONDARY_SERVICES: [&str; 2] = ["bind9-1", "bind9-2"];

/// The longest a `docker compose` command may run.
const COMPOSE_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);

/// The TSIG key bind9-1 pulls over TLS with, as its named.conf spells it.
const COMPOSE_XOT_KEY: &str = "xot-key";
const COMPOSE_XOT_SECRET: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// The stack shared by every test of the run, started on first use.
static COMPOSE_STACK: OnceLock<ComposeStack> = OnceLock::new();

impl TestApp {
    /// Start a test application using the Docker Compose services.
    pub(crate) async fn start_compose() -> Self {
        common::install_crypto_provider();
        let compose_stack = COMPOSE_STACK.get_or_init(ComposeStack::start);
        let client = Client::new();

        wait_for_compose_api(&client).await;
        register_compose_secondaries(&client).await;

        Self {
            runtime: TestRuntime::Compose(compose_stack),
            client,
            base_url: COMPOSE_API_BASE_URL.to_string(),
            dns_port: None,
            dns_tls_port: None,
            tls_cert: None,
            dns_secondary_ports: SECONDARY_PORTS.to_vec(),
            namespace: common::test_namespace(),
            auth_token: None,
        }
    }
}

/// Register the stack's BIND9 services as secondaries, and the key bind9-1
/// signs with; the stack is reused across tests, so what exists is left alone.
async fn register_compose_secondaries(client: &Client) {
    for name in COMPOSE_SECONDARY_SERVICES {
        if probe_api_resource(client, &format!("/secondaries/{name}")).await {
            continue;
        }

        post(
            client,
            "/secondaries",
            json!({ "name": name, "address": format!("{name}:53") }),
            &[StatusCode::CREATED],
        )
        .await;
    }

    // RFC 9103, Section 7.5: over TLS the key is required beside the
    // address, in a role that may transfer all zones.
    if probe_api_resource(client, &format!("/tsig-keys/{COMPOSE_XOT_KEY}")).await {
        return;
    }

    post(
        client,
        "/roles",
        json!({ "name": "secondaries" }),
        &[StatusCode::CREATED, StatusCode::CONFLICT],
    )
    .await;
    post(
        client,
        "/roles/secondaries/grants",
        json!({ "actions": ["zone:transfer"] }),
        &[StatusCode::CREATED],
    )
    .await;
    post(
        client,
        "/tsig-keys",
        json!({
            "name": COMPOSE_XOT_KEY,
            "secret": COMPOSE_XOT_SECRET,
            "role_name": "secondaries"
        }),
        &[StatusCode::CREATED],
    )
    .await;
}

/// Return whether the compose API serves `path`.
async fn probe_api_resource(client: &Client, path: &str) -> bool {
    client
        .get(format!("{COMPOSE_API_BASE_URL}{path}"))
        .send()
        .await
        .unwrap_or_else(|error| panic!("GET {path}: {error}"))
        .status()
        == StatusCode::OK
}

/// POST `request` to the compose API, accepting one of `allowed` statuses.
async fn post(client: &Client, path: &str, request: Value, allowed: &[StatusCode]) {
    let response = client
        .post(format!("{COMPOSE_API_BASE_URL}{path}"))
        .json(&request)
        .send()
        .await
        .unwrap_or_else(|error| panic!("POST {path}: {error}"));

    assert!(
        allowed.contains(&response.status()),
        "POST {path} answered {}",
        response.status()
    );
}

/// The Docker Compose project hosting bindizr and its BIND9 secondaries for
/// the DNS-verified run.
#[derive(Debug)]
pub(crate) struct ComposeStack {
    project_name: String,
    compose_dir: PathBuf,
}

impl ComposeStack {
    /// Start the Compose stack used by the test harness.
    fn start() -> Self {
        let stack = Self {
            project_name: COMPOSE_PROJECT_NAME.to_string(),
            compose_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        };

        if is_compose_stack_reachable() {
            eprintln!("Reusing the running Docker Compose DNS E2E stack...");
        } else {
            eprintln!("Starting Docker Compose DNS E2E stack...");
            stack.run_compose(&["up", "-d", "--build", "bindizr", "bind9-1", "bind9-2"]);
            stack.run_compose(&["ps"]);
        }

        stack
    }

    /// Build a CLI command that runs inside the Compose daemon container.
    pub(crate) fn cli_command(&self) -> Command {
        let mut command = self.compose_command();
        command.args(["exec", "-T", "bindizr", "bindizr"]);
        command
    }

    /// Build a Docker Compose command for the test project.
    fn compose_command(&self) -> Command {
        let mut command = Command::new("docker");
        command.arg("compose").arg("-p").arg(&self.project_name);

        for file in compose_files() {
            command.arg("-f").arg(file);
        }

        command.current_dir(&self.compose_dir);

        command
    }

    /// Run a Compose command and assert that it succeeds.
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

        let started = Instant::now();
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .expect("failed to check docker compose status")
            {
                break status;
            }

            if started.elapsed() > COMPOSE_COMMAND_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "docker compose {} timed out after {} seconds",
                    args.join(" "),
                    COMPOSE_COMMAND_TIMEOUT.as_secs()
                );
            }

            thread::sleep(Duration::from_secs(1));
        };

        assert!(
            status.success(),
            "docker compose {} failed with status {status}",
            args.join(" ")
        );
    }
}

/// Return whether the expected Compose service ports are reachable.
fn is_compose_stack_reachable() -> bool {
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

/// List the compose files; the ARM override swaps the amd64-only ISC bind9
/// image for a multi-arch one.
fn compose_files() -> Vec<&'static str> {
    if common::read_env_flag(ARM_STACK_ENV) {
        vec![COMPOSE_FILE, ARM_COMPOSE_FILE]
    } else {
        vec![COMPOSE_FILE]
    }
}

/// Wait until the Compose API is ready for requests.
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

        time::sleep(Duration::from_secs(1)).await;
    }

    panic!("bindizr API did not become ready at {COMPOSE_API_BASE_URL}");
}
