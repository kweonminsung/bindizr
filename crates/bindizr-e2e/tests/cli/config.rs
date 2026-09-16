use std::process::{Command, Stdio};

use crate::common::{TestApp, assert_cli_failure_contains, assert_cli_success};

const VALID_CONFIG: &str = r#"
[api]
listen_addr = "127.0.0.1"
listen_port = 8000

[api.authentication]
required = false

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

/// Run `bindizr config check` against the host binary directly: the command is
/// offline, so no daemon or compose stack is involved.
fn run_config_check(file: Option<&str>, env: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bindizr-e2e-server"));
    command.args(["config", "check"]);
    if let Some(file) = file {
        command.args(["--config", file]);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    command
        .stdin(Stdio::null())
        .output()
        .expect("failed to run bindizr CLI")
}

/// Verify that config check accepts a config flag.
#[test]
#[serial_test::serial(bindizr_e2e)]
fn config_check_accepts_a_config_flag() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = temp_dir.path().join("bindizr.conf.toml");
    std::fs::write(&config_path, VALID_CONFIG).expect("failed to write config");

    let path = config_path.to_str().expect("config path was not UTF-8");
    let output = run_config_check(Some(path), &[]);

    assert_cli_success(&["config", "check", "--config", path], &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(path));
    assert!(stdout.contains("valid"));
}

/// Verify that config check uses config path env without argument.
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

/// Verify that config check rejects invalid config.
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
        &["config", "check", "--config", path],
        &output,
        "Invalid Bindizr configuration",
    );
}

/// Verify that config check rejects missing file.
#[test]
#[serial_test::serial(bindizr_e2e)]
fn config_check_rejects_missing_file() {
    let output = run_config_check(Some("/nonexistent/bindizr.conf.toml"), &[]);

    assert_cli_failure_contains(
        &[
            "config",
            "check",
            "--config",
            "/nonexistent/bindizr.conf.toml",
        ],
        &output,
        "does not exist",
    );
}

/// Verify that config list and get show loaded config.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn config_list_and_get_show_loaded_config() {
    let app = TestApp::start().await;

    let listed = app.run_cli_success(&["config", "list"]).await;
    assert!(listed.contains("[api]"));
    assert!(listed.contains("[dns]"));
    assert!(listed.contains("[dns.nsupdate]"));
    assert!(listed.contains("[dns.notify]"));

    let value = app
        .run_cli_success(&["config", "get", "api.authentication.required"])
        .await;
    assert_eq!(value.trim(), "false");

    let args = ["config", "get", "no.such.key"];
    let missing = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &missing, "Unknown configuration key");
}

/// Verify that config reload takes the file again and refuses what it cannot adopt.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn config_reload_takes_the_file_again_and_refuses_what_it_cannot_adopt() {
    let app = TestApp::start_local().await;
    let path = app.config_path();
    let original = std::fs::read_to_string(&path).expect("config file");

    assert_eq!(
        app.run_cli_success(&["config", "get", "logging.level"])
            .await
            .trim(),
        "error"
    );

    std::fs::write(
        &path,
        original.replace(r#"level = "error""#, r#"level = "warn""#),
    )
    .expect("rewrite config");
    let reloaded = app.run_cli_success(&["config", "reload"]).await;
    assert!(reloaded.contains("logging"), "{reloaded}");
    assert_eq!(
        app.run_cli_success(&["config", "get", "logging.level"])
            .await
            .trim(),
        "warn"
    );

    // Bound to a listening socket, so the file is refused whole and the
    // running configuration is left describing the running process.
    let port = app
        .run_cli_success(&["config", "get", "api.listen_port"])
        .await
        .trim()
        .to_string();
    std::fs::write(
        &path,
        original.replace(&format!("listen_port = {port}"), "listen_port = 1"),
    )
    .expect("rewrite config");
    let args = ["config", "reload"];
    let refused = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &refused, "fixed while bindizr runs");
    assert_eq!(
        app.run_cli_success(&["config", "get", "api.listen_port"])
            .await
            .trim(),
        port
    );

    std::fs::write(&path, original).expect("restore config");
}
