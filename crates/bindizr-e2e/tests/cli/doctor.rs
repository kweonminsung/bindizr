use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::time;

use crate::common;
use crate::common::TestApp;

/// A configuration file that passes validation.
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
    fs::write(&config_path, VALID_CONFIG).expect("failed to write config");
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
    let mut output = app.run_cli(&args, None).await;

    for _ in 0..30 {
        if output.status.success() {
            break;
        }
        time::sleep(Duration::from_secs(1)).await;
        output = app.run_cli(&args, None).await;
    }

    common::assert_cli_success(&args, &output);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Config valid"));
    assert!(stdout.contains("Daemon running"));
    assert!(stdout.contains("API reachable"));
    assert!(stdout.contains("Database connected"));
    assert!(stdout.contains("DNS server reachable"));
    assert!(stdout.contains("installation looks"));

    if app.has_dns_secondaries() {
        assert!(stdout.contains("Secondary in sync"));
        assert!(stdout.contains("NOTIFY accepted"));
    } else {
        assert!(stdout.contains("No enabled secondaries"));
    }
}

/// Verify that `doctor` runs the offline checks when no daemon is up.
#[test]
#[serial_test::serial(bindizr_e2e)]
fn doctor_runs_the_offline_checks_when_no_daemon_runs() {
    // Ports nothing on this host holds, so the port checks have a pass to report.
    let config = VALID_CONFIG
        .replace(
            "listen_port = 8000",
            &format!("listen_port = {}", common::reserve_tcp_port()),
        )
        .replace(
            "listen_port = 5300",
            &format!("listen_port = {}", common::reserve_tcp_port()),
        );

    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = temp_dir.path().join("bindizr.conf.toml");
    fs::write(&config_path, config).expect("failed to write config");
    let path = config_path.to_str().expect("config path was not UTF-8");

    // The host binary, like `config check`: no daemon answers its socket.
    let args = ["doctor", "-c", path];
    let output = Command::new(env!("CARGO_BIN_EXE_bindizr-e2e-server"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("failed to run bindizr CLI");

    common::assert_cli_failure_contains(&args, &output, "failing check");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Daemon not reachable"), "{stdout}");

    // The fixture's SQLite path is relative, which only the service can resolve.
    assert!(stdout.contains("Database check skipped"), "{stdout}");
    assert!(stdout.contains("DNS port free"), "{stdout}");
    assert!(stdout.contains("API port free"), "{stdout}");
}

/// Verify that the first check reports path and override errors in structured output.
#[test]
#[serial_test::serial(bindizr_e2e)]
fn doctor_reports_config_path_and_override_failures() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = temp_dir.path().join("bindizr.toml");
    let looping_path = temp_dir.path().join("loop.toml");
    let invalid = OsString::from_vec(b"private-value-\xff".to_vec());

    fs::write(&config_path, VALID_CONFIG).expect("failed to write config");
    symlink(&looping_path, &looping_path).expect("failed to create config symlink");

    for (path, env, expected) in [
        (
            Some(&looping_path),
            None,
            "failed to read the configuration file",
        ),
        (
            None,
            Some("BINDIZR_CONFIG_PATH"),
            "BINDIZR_CONFIG_PATH environment variable is not valid UTF-8",
        ),
        (
            Some(&config_path),
            Some("BINDIZR_API_LISTEN_PORT"),
            "BINDIZR_API_LISTEN_PORT environment variable is not valid UTF-8",
        ),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bindizr-e2e-server"));
        command
            .args(["doctor", "--output", "json"])
            .stdin(Stdio::null());
        if let Some(path) = path {
            command.arg("-c").arg(path);
        }
        if let Some(name) = env {
            command.env(name, &invalid);
        }
        let output = command.output().expect("failed to run bindizr CLI");
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("doctor did not return JSON");
        let first = &report["checks"][0];
        let message = first["message"]
            .as_str()
            .expect("the config check has no message");

        assert!(!output.status.success());
        assert_eq!(first["status"], "failed");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("private-value"), "{message}");
    }
}
