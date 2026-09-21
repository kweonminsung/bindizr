use std::process::{Command, Stdio};

use crate::common::{TestApp, assert_cli_failure_contains, assert_cli_success};

const VALID_CONFIG: &str = r#"
[api]
listen_addr = "127.0.0.1"
listen_port = 8000


[database]
type = "sqlite"

[database.sqlite]
file_path = "bindizr.sqlite"

[dns]
listen_addr = "127.0.0.1"
listen_port = 5300
secondary_addrs = ""

[logging]
level = "info"
"#;

/// Verify that `doctor` reports healthy installation.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn doctor_reports_healthy_installation() {
    let app = TestApp::start().await;

    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = temp_dir.path().join("bindizr.conf.toml");
    std::fs::write(&config_path, VALID_CONFIG).expect("failed to write config");
    let path = config_path.to_str().expect("config path was not UTF-8");

    // Compose mode runs the CLI inside the container, where the default
    // config file exists; locally /etc/bindizr may not, so pass a valid file.
    let args: Vec<&str> = if app.has_dns_secondaries() {
        vec!["doctor"]
    } else {
        vec!["doctor", "-c", path]
    };

    // Secondaries transfer asynchronously after NOTIFY, so behind a burst of
    // zone writes doctor can catch them one catalog serial short.
    let mut result = app.run_cli(&args).await;
    for _ in 0..30 {
        if result.status.success() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        result = app.run_cli(&args).await;
    }
    assert_cli_success(&args, &result);
    let output = String::from_utf8(result.stdout).expect("CLI stdout was not UTF-8");

    assert!(output.contains("Config valid"));
    assert!(output.contains("Daemon running"));
    assert!(output.contains("API reachable"));
    assert!(output.contains("Database connected"));
    assert!(output.contains("DNS server reachable"));
    assert!(output.contains("installation looks"));

    if app.has_dns_secondaries() {
        assert!(output.contains("Secondary in sync"));
        assert!(output.contains("NOTIFY accepted"));
    } else {
        assert!(output.contains("No secondaries configured"));
    }
}

/// Verify that `doctor` runs the offline checks when no daemon is up.
#[test]
#[serial_test::serial(bindizr_e2e)]
fn doctor_without_a_daemon_runs_the_offline_checks() {
    // Ports nothing on this host holds, so the port checks have a pass to report.
    let free_port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind an ephemeral port")
            .local_addr()
            .expect("local address")
            .port()
    };
    let config = VALID_CONFIG
        .replace(
            "listen_port = 8000",
            &format!("listen_port = {}", free_port()),
        )
        .replace(
            "listen_port = 5300",
            &format!("listen_port = {}", free_port()),
        );

    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = temp_dir.path().join("bindizr.conf.toml");
    std::fs::write(&config_path, config).expect("failed to write config");
    let path = config_path.to_str().expect("config path was not UTF-8");

    // The host binary, like `config check`: no daemon answers its socket.
    let args = ["doctor", "-c", path];
    let output = Command::new(env!("CARGO_BIN_EXE_bindizr-e2e-server"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("failed to run bindizr CLI");

    assert_cli_failure_contains(&args, &output, "failing check");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Daemon not reachable"), "{stdout}");
    // The fixture's SQLite path is relative, which only the service can resolve.
    assert!(stdout.contains("Database check skipped"), "{stdout}");
    assert!(stdout.contains("DNS port free"), "{stdout}");
    assert!(stdout.contains("API port free"), "{stdout}");
}
