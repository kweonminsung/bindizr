//! Checks that go through a running daemon: its socket, its HTTP API, and
//! what it reports about its database, listener, and secondaries.

use std::{net::SocketAddr, time::Duration};

use axum::http::StatusCode;
use bindizr_core::{
    config::Config,
    dns::{Serial, address::loopback_if_unspecified},
};
use bindizr_service::types::SecondaryStatus;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::Report;
use crate::{
    cli::output::display_transfer_summary,
    socket::{
        client,
        types::{DaemonCommand, DaemonDoctorResponse, DaemonStatusResponse, DoctorCheckStatus},
    },
};

/// Why the API did not answer a probe as a reachable API.
#[derive(Debug, Error)]
enum ProbeApiError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("timed out")]
    TimedOut,
    #[error("unexpected response: {line}")]
    UnexpectedResponse { line: String },
    /// The API answers but cannot serve; the status line says why.
    #[error("{line}")]
    ServerFault { line: String },
}

const API_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Check whether the daemon responds through its control socket.
pub(crate) async fn check_running(report: &mut Report) -> bool {
    let status = client::send_control_command::<DaemonStatusResponse>(DaemonCommand::Status)
        .await
        .map(|response| response.data);
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
pub(crate) async fn check_api(config: &Config, report: &mut Report) {
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
async fn probe_http_status_line(addr: SocketAddr) -> Result<String, ProbeApiError> {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await?;
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            addr
        );
        stream.write_all(request.as_bytes()).await?;

        // TCP may split the response; read until the status line is complete.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if buf.contains(&b'\n') || buf.len() >= 1024 {
                break;
            }
        }
        Ok::<_, ProbeApiError>(String::from_utf8_lossy(&buf).to_string())
    };
    let response = tokio::time::timeout(API_CHECK_TIMEOUT, exchange)
        .await
        .map_err(|_| ProbeApiError::TimedOut)??;

    let status_line = response.lines().next().unwrap_or_default().trim();
    if !status_line.starts_with("HTTP/") {
        return Err(ProbeApiError::UnexpectedResponse {
            line: status_line.to_string(),
        });
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
        return Err(ProbeApiError::ServerFault {
            line: status_line.to_string(),
        });
    }
    Ok(status_line.to_string())
}

/// Check database, DNS listener, and secondary status through the daemon.
pub(crate) async fn check_services(report: &mut Report) {
    let doctor = match client::send_command::<DaemonDoctorResponse>(DaemonCommand::Doctor).await {
        Ok(res) => res.data,
        Err(e) => {
            report.fail(format!("Daemon-side checks failed: {}", e.message));
            return;
        }
    };

    let database_failed = doctor.database.status == DoctorCheckStatus::Failed;
    report.push(doctor.database);
    report.push(doctor.dns_server);

    if database_failed {
        report.skip("Secondary checks skipped: the database did not answer");
        return;
    }
    if doctor.secondaries.is_empty() {
        report.skip("No enabled secondaries");
        return;
    }

    // These serials are the catalog zone's, unlike `zone status`, so say so.
    let catalog_zone = &doctor.catalog_zone_name;
    for secondary in &doctor.secondaries {
        let serial = secondary.visible_serial.map_or(0, Serial::as_u32);
        match secondary.status {
            SecondaryStatus::InSync | SecondaryStatus::Reachable => report.ok(format!(
                "Secondary {}: {} (catalog zone {} at serial {})",
                secondary.status, secondary.address, catalog_zone, serial
            )),
            SecondaryStatus::Unreachable => report.fail(format!(
                "Secondary {}: {} ({})",
                secondary.status,
                secondary.address,
                secondary.error.as_deref().unwrap_or("unknown error")
            )),
            SecondaryStatus::Lagging | SecondaryStatus::Ahead => report.fail(format!(
                "Secondary {}: {} (catalog zone {} at serial {}; bindizr serves {})",
                secondary.status,
                secondary.address,
                catalog_zone,
                serial,
                doctor.catalog_serial.map_or(0, Serial::as_u32)
            )),
        }
    }

    for notify in &doctor.notifies {
        match &notify.error {
            None => report.ok(format!("NOTIFY accepted: {}", notify.address)),
            Some(e) => report.fail(format!("NOTIFY rejected: {} ({})", notify.address, e)),
        }
    }

    // What Bindizr served each secondary is information, not a verdict.
    for transfer in &doctor.transfers {
        let line = format!(
            "Transfers to {}: {}",
            transfer.address,
            display_transfer_summary(&transfer.summary)
        );
        if transfer.summary.zones == 0 {
            report.skip(line);
        } else {
            report.ok(line);
        }
    }
}
