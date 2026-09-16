//! Checks that go through a running daemon: its socket, its HTTP API, and
//! what it reports about its database, listener, and secondaries.

use std::{net::SocketAddr, time::Duration};

use bindizr_core::config::BindizrConfig;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::Report;
use crate::{
    net::loopback_if_unspecified,
    socket::{
        client,
        types::{DaemonCommandKind, DaemonDoctorResponse},
    },
};

const API_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Check whether the daemon responds through its control socket.
pub(crate) async fn check_running(report: &mut Report) -> bool {
    match client::fetch_status().await {
        Ok(status) => {
            let pid = status
                .pid
                .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
            report.ok(format!(
                "Daemon running: pid {} (version {})",
                pid, status.version
            ));
            true
        }
        Err(e) => {
            report.fail(format!("Daemon not reachable: {}", e.message));
            false
        }
    }
}

/// Check API reachability at the daemon's configured address.
pub(crate) async fn check_api(config: &BindizrConfig, report: &mut Report) {
    let addr = SocketAddr::new(
        loopback_if_unspecified(config.api.listen_addr),
        config.api.listen_port,
    );

    // Under TLS the probe stops at the connection: a listening daemon has
    // already loaded the pair, and speaking TLS here would mean trusting
    // whatever it presents.
    if config.api.tls_files().is_some() {
        match tokio::time::timeout(API_CHECK_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => report.ok(format!(
                "API listening: https://{} (TLS handshake not attempted)",
                addr
            )),
            Ok(Err(e)) => report.fail(format!("API not reachable: https://{} ({})", addr, e)),
            Err(_) => report.fail(format!("API not reachable: https://{} (timed out)", addr)),
        }
        return;
    }

    match probe_http_status_line(addr).await {
        Ok(status_line) => report.ok(format!("API reachable: http://{} ({})", addr, status_line)),
        Err(e) => report.fail(format!("API not reachable: http://{} ({})", addr, e)),
    }
}

/// Minimal HTTP GET returning the status line; a plain-HTTP API needs no full
/// HTTP client dependency here.
async fn probe_http_status_line(addr: SocketAddr) -> Result<String, String> {
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

/// Check database, DNS listener, and secondary status through the daemon.
pub(crate) async fn check_services(report: &mut Report) {
    let res = match client::send_command(DaemonCommandKind::Doctor, ()).await {
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
