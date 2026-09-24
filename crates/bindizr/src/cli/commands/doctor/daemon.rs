//! Checks that go through a running daemon: its socket, its HTTP API, and
//! what it reports about its database, listener, and secondaries.

use std::{net::SocketAddr, time::Duration};

use axum::http::StatusCode;
use bindizr_core::{config::BindizrConfig, dns::address::loopback_if_unspecified};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::Report;
use crate::{
    cli::output::parse_response,
    socket::{
        client,
        types::{DaemonCommandKind, DaemonDoctorResponse, DaemonStatusResponse},
    },
};

const API_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Check whether the daemon responds through its control socket.
pub(crate) async fn check_running(report: &mut Report) -> bool {
    let status = client::send_control_command(DaemonCommandKind::Status)
        .await
        .and_then(|response| Ok(parse_response::<DaemonStatusResponse>(&response.data)?));
    match status {
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
    if !status_line.starts_with("HTTP/") {
        return Err(format!("unexpected response: {}", status_line));
    }
    // A 5xx to this request means the API is answering but cannot serve, which
    // is a failing check rather than a reachable API.
    let answered_5xx = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .is_some_and(|status| status.is_server_error());
    if answered_5xx {
        return Err(status_line.to_string());
    }
    Ok(status_line.to_string())
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
        report.skip("No enabled secondaries");
        return;
    }

    // These serials are the catalog zone's, unlike `zone status`, so say so.
    let catalog_zone = &doctor.catalog_zone;
    for secondary in &doctor.secondaries {
        let serial = secondary.visible_serial.unwrap_or_default();
        match secondary.status.as_str() {
            "in_sync" => report.ok(format!(
                "Secondary in sync: {} (catalog zone {} at serial {})",
                secondary.address, catalog_zone, serial
            )),
            "reachable" => report.ok(format!(
                "Secondary reachable: {} (catalog zone {} at serial {})",
                secondary.address, catalog_zone, serial
            )),
            "unreachable" => report.fail(format!(
                "Secondary unreachable: {} ({})",
                secondary.address,
                secondary.error.as_deref().unwrap_or("unknown error")
            )),
            _ => report.fail(format!(
                "Secondary out of sync: {} (catalog zone {} at serial {}; bindizr serves {})",
                secondary.address,
                catalog_zone,
                serial,
                doctor.catalog_serial.unwrap_or_default()
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
