use std::process::{Command, Stdio};

use crate::common::{TestApp, assert_cli_failure_contains, assert_cli_success};

const VALID_CONFIG: &str = r#"
[api]
listen_addr = "127.0.0.1"
listen_port = 8000
require_authentication = false

[database]
type = "sqlite"

[database.sqlite]
file_path = "bindizr.sqlite"

[dns]
listen_addr = "127.0.0.1"
listen_port = 5300
secondary_addrs = ""

[logging]
log_level = "info"
"#;

/// Run `bindizr config check` against the host binary directly: the command is
/// offline, so no daemon or compose stack is involved.
fn run_config_check(file: Option<&str>, env: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bindizr-e2e-server"));
    command.args(["config", "check"]);
    if let Some(file) = file {
        command.arg(file);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    command
        .stdin(Stdio::null())
        .output()
        .expect("failed to run bindizr CLI")
}

#[test]
#[serial_test::serial(bindizr_e2e)]
fn config_check_accepts_file_argument() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = temp_dir.path().join("bindizr.conf.toml");
    std::fs::write(&config_path, VALID_CONFIG).expect("failed to write config");

    let path = config_path.to_str().expect("config path was not UTF-8");
    let output = run_config_check(Some(path), &[]);

    assert_cli_success(&["config", "check", path], &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(path));
    assert!(stdout.contains("valid"));
}

#[test]
#[serial_test::serial(bindizr_e2e)]
fn config_check_uses_config_path_env_without_argument() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = temp_dir.path().join("bindizr.conf.toml");
    std::fs::write(&config_path, VALID_CONFIG).expect("failed to write config");

    let path = config_path.to_str().expect("config path was not UTF-8");
    let output = run_config_check(None, &[("BINDIZR_CONFIG_PATH", path)]);

    assert_cli_success(&["config", "check"], &output);
    assert!(String::from_utf8_lossy(&output.stdout).contains(path));
}

#[test]
#[serial_test::serial(bindizr_e2e)]
fn config_check_rejects_invalid_config() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = temp_dir.path().join("bindizr.conf.toml");
    std::fs::write(&config_path, "[api]\nlisten_addr = \"not-an-ip\"\n")
        .expect("failed to write config");

    let path = config_path.to_str().expect("config path was not UTF-8");
    let output = run_config_check(Some(path), &[]);

    assert_cli_failure_contains(
        &["config", "check", path],
        &output,
        "Invalid Bindizr configuration",
    );
}

#[test]
#[serial_test::serial(bindizr_e2e)]
fn config_check_rejects_missing_file() {
    let output = run_config_check(Some("/nonexistent/bindizr.conf.toml"), &[]);

    assert_cli_failure_contains(
        &["config", "check", "/nonexistent/bindizr.conf.toml"],
        &output,
        "does not exist",
    );
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn config_list_and_get_show_loaded_config() {
    let app = TestApp::start().await;

    let listed = app.run_cli_success(&["config", "list"]).await;
    assert!(listed.contains("[api]"));
    assert!(listed.contains("[dns]"));
    assert!(listed.contains("nsupdate_allow_unsigned"));

    let value = app
        .run_cli_success(&["config", "get", "api.require_authentication"])
        .await;
    assert_eq!(value.trim(), "false");

    let args = ["config", "get", "no.such.key"];
    let missing = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &missing, "Unknown configuration key");
}
