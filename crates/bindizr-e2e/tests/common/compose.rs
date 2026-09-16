//! Lifecycle of the shared BIND9 Compose stack.

use std::{
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

use reqwest::{Client, StatusCode};

use super::{TestApp, TestRuntime, env_flag, test_namespace};

const COMPOSE_FILE: &str = "docker-compose.yml";
const ARM_COMPOSE_FILE: &str = "docker-compose.arm.yml";
const COMPOSE_PROJECT_NAME: &str = "bindizr-e2e-dns";
const COMPOSE_API_BASE_URL: &str = "http://127.0.0.1:8000";
const ARM_STACK_ENV: &str = "BINDIZR_E2E_ARM";
const SECONDARY_PORTS: [u16; 2] = [1053, 1054];
const COMPOSE_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
static COMPOSE_STACK: OnceLock<ComposeStack> = OnceLock::new();

impl TestApp {
    /// Start a test application using the Docker Compose services.
    pub(crate) async fn start_compose() -> Self {
        let compose_stack = COMPOSE_STACK.get_or_init(ComposeStack::start);
        let client = Client::new();
        wait_for_compose_api(&client).await;

        Self {
            runtime: TestRuntime::Compose(compose_stack),
            client,
            base_url: COMPOSE_API_BASE_URL.to_string(),
            dns_port: None,
            dns_secondary_ports: SECONDARY_PORTS.to_vec(),
            namespace: test_namespace(),
            auth_token: None,
        }
    }
}

/// The Docker Compose project hosting bindizr and its BIND9 secondaries for
/// the DNS-verified run.
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

/// Check whether the expected Compose service ports are reachable.
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

/// The ARM override swaps the amd64-only ISC bind9 image for a multi-arch one.
fn compose_files() -> Vec<&'static str> {
    if env_flag(ARM_STACK_ENV) {
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

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!("bindizr API did not become ready at {COMPOSE_API_BASE_URL}");
}
