use std::{fmt, net::SocketAddr, time::Duration};

use bindizr_core::config;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    cli::error::CliError,
    net::loopback_if_unspecified,
    socket::{
        client::DaemonSocketClient,
        types::{DaemonCommandKind, DaemonDoctorResponse, DaemonStatusResponse},
    },
};

const API_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Tallies check outcomes so the exit code can reflect them.
struct Report {
    failures: usize,
}

impl Report {
    fn ok(&mut self, message: impl fmt::Display) {
        println!("[\x1b[32mOK\x1b[0m] {}", message);
    }

    fn fail(&mut self, message: impl fmt::Display) {
        self.failures += 1;
        println!("[\x1b[31mFAIL\x1b[0m] {}", message);
    }

    fn skip(&mut self, message: impl fmt::Display) {
        println!("[\x1b[33mSKIP\x1b[0m] {}", message);
    }
}

/// Handle the `doctor` subcommand by verifying the installation end to end.
pub(crate) async fn handle_command(config_file: Option<String>) -> Result<(), CliError> {
    println!("Bindizr Doctor");
    println!();

    let mut report = Report { failures: 0 };

    let path = config::resolve_config_path(config_file.as_deref());
    match config::load_config_file(&path) {
        Ok(_) => report.ok(format!("Config valid: {}", path)),
        Err(e) => report.fail(format!("Config invalid: {}", e)),
    }

    let client = DaemonSocketClient::new();
    let status = check_daemon(&client, &mut report).await;

    match &status {
        Some(status) => {
            check_api(&status.config, &mut report).await;
            check_daemon_side(&client, &mut report).await;
        }
        None => report.skip("API, database, and DNS checks skipped: daemon is not running"),
    }

    println!();
    if report.failures == 0 {
        println!("Result: installation looks \x1b[32mhealthy\x1b[0m");
        Ok(())
    } else {
        Err(CliError::from(format!(
            "installation has {} failing check(s)",
            report.failures
        )))
    }
}

async fn check_daemon(
    client: &DaemonSocketClient,
    report: &mut Report,
) -> Option<DaemonStatusResponse> {
    match client.status().await {
        Ok(status) => {
            let pid = status
                .pid
                .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
            report.ok(format!(
                "Daemon running: pid {} (version {})",
                pid, status.version
            ));
            Some(status)
        }
        Err(e) => {
            report.fail(format!("Daemon not reachable: {}", e.message));
            None
        }
    }
}

async fn check_api(config: &bindizr_core::config::BindizrConfig, report: &mut Report) {
    let addr = SocketAddr::new(
        loopback_if_unspecified(config.api.listen_addr),
        config.api.listen_port,
    );

    match http_get_status_line(addr).await {
        Ok(status_line) => report.ok(format!("API reachable: http://{} ({})", addr, status_line)),
        Err(e) => report.fail(format!("API not reachable: http://{} ({})", addr, e)),
    }
}

/// Minimal HTTP GET returning the status line; the API is plain HTTP on
/// localhost, so a full HTTP client dependency is unnecessary.
async fn http_get_status_line(addr: SocketAddr) -> Result<String, String> {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            addr
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| e.to_string())?;

        // TCP may split the response; read until the status line is complete.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            let read = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if buf.contains(&b'\n') || buf.len() >= 1024 {
                break;
            }
        }
        Ok::<_, String>(String::from_utf8_lossy(&buf).to_string())
    };

    let response = tokio::time::timeout(API_CHECK_TIMEOUT, exchange)
        .await
        .map_err(|_| "timed out".to_string())??;

    let status_line = response.lines().next().unwrap_or_default().trim();
    if status_line.starts_with("HTTP/") {
        Ok(status_line.to_string())
    } else {
        Err(format!("unexpected response: {}", status_line))
    }
}

async fn check_daemon_side(client: &DaemonSocketClient, report: &mut Report) {
    let res = match client.send_command(DaemonCommandKind::Doctor, ()).await {
        Ok(res) => res,
        Err(e) => {
            report.fail(format!("Daemon-side checks failed: {}", e.message));
            return;
        }
    };

    let doctor: DaemonDoctorResponse = match serde_json::from_value(res.data) {
        Ok(doctor) => doctor,
        Err(e) => {
            report.fail(format!("Doctor response was malformed: {}", e));
            return;
        }
    };

    if doctor.database.ok {
        report.ok(format!("Database connected: {}", doctor.database.detail));
    } else {
        report.fail(format!(
            "Database not reachable: {}",
            doctor.database.detail
        ));
    }

    if doctor.dns_server.ok {
        report.ok(format!(
            "DNS server reachable: {}",
            doctor.dns_server.detail
        ));
    } else {
        report.fail(format!(
            "DNS server not reachable: {}",
            doctor.dns_server.detail
        ));
    }

    if doctor.secondaries.is_empty() {
        report.skip("No secondaries configured");
        return;
    }

    for secondary in &doctor.secondaries {
        match (secondary.serial, doctor.catalog_serial) {
            (Some(serial), Some(expected)) if serial == expected => report.ok(format!(
                "Secondary in sync: {} (catalog serial {})",
                secondary.address, serial
            )),
            (Some(serial), Some(expected)) => report.fail(format!(
                "Secondary out of sync: {} (serving catalog serial {}, expected {})",
                secondary.address, serial, expected
            )),
            (Some(serial), None) => report.ok(format!(
                "Secondary reachable: {} (catalog serial {})",
                secondary.address, serial
            )),
            _ => report.fail(format!(
                "Secondary unreachable: {} ({})",
                secondary.address,
                secondary.error.as_deref().unwrap_or("unknown error")
            )),
        }
    }

    for notify in &doctor.notifies {
        match &notify.error {
            None => report.ok(format!("NOTIFY accepted: {}", notify.address)),
            Some(e) => report.fail(format!("NOTIFY rejected: {} ({})", notify.address, e)),
        }
    }
}
