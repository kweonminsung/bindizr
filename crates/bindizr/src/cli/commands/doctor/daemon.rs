//! Checks that go through a running daemon: its socket, its HTTP API, and
//! what it reports about its database, listener, and secondaries.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use axum::http::StatusCode;
use axum::http::status::InvalidStatusCode;
use bindizr_core::config::Config;
use bindizr_core::dns::{Serial, address};
use bindizr_service::types::SecondaryStatus;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time;

use crate::cli::commands::doctor::Report;
use crate::cli::output;
use crate::socket::client;
use crate::socket::types::{
    DaemonCommand, DaemonDoctorResponse, DaemonStatusResponse, DoctorCheckStatus,
};

/// An API that does not answer must become a failed check, not a hang.
const API_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_STATUS_LINE_BYTES: u64 = 1024;

/// Why the API did not answer a probe as a reachable API.
#[derive(Debug, Error)]
enum ProbeApiError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("timed out")]
    TimedOut(#[source] time::error::Elapsed),
    #[error("invalid or incomplete HTTP status line")]
    InvalidStatusLine,
    #[error("invalid HTTP status code")]
    StatusCode(#[source] InvalidStatusCode),
    /// The API answers but cannot serve; the status line says why.
    #[error("{line}")]
    ServerFault { line: String },
}

/// Return whether the daemon responds through its control socket.
pub(crate) async fn check_running(report: &mut Report) -> bool {
    let status = client::send_control_command::<DaemonStatusResponse>(DaemonCommand::Status)
        .await
        .map(|response| response.data);

    match status {
        Ok(status) => {
            let pid = status.pid;
            report.ok(format!(
                "Daemon running: pid {pid} (version {})",
                status.version
            ));

            true
        }
        Err(error) => {
            report.fail(format!("Daemon not reachable: {}", error.message));
            false
        }
    }
}

/// Check API reachability at the daemon's configured address.
pub(crate) async fn check_api(config: &Config, report: &mut Report) {
    let addr = SocketAddr::new(
        address::loopback_if_unspecified(config.api.listen_addr),
        config.api.listen_port,
    );

    // Probe TCP only under TLS: the daemon loaded its keypair; this check has no certificate trust.
    if config.api.tls.tls_files().is_some() {
        match time::timeout(API_CHECK_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => report.ok(format!(
                "API listening: https://{addr} (TLS handshake not attempted)"
            )),
            Ok(Err(error)) => {
                report.fail(format!("API not reachable: https://{addr} ({error})"));
            }
            Err(_) => report.fail(format!("API not reachable: https://{addr} (timed out)")),
        }

        return;
    }

    match probe_http_status_line(addr).await {
        Ok(status_line) => report.ok(format!("API reachable: http://{addr} ({status_line})")),
        Err(error) => report.fail(format!("API not reachable: http://{addr} ({error})")),
    }
}

/// Send a minimal HTTP GET and return the status line; a plain-HTTP API needs
/// no full HTTP client dependency here.
async fn probe_http_status_line(addr: SocketAddr) -> Result<String, ProbeApiError> {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await?;

        let request = format!("GET / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");

        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();

        BufReader::new(stream)
            .take(MAX_STATUS_LINE_BYTES)
            .read_until(b'\n', &mut response)
            .await?;

        parse_http_status_line(&response)
    };
    time::timeout(API_CHECK_TIMEOUT, exchange)
        .await
        .map_err(ProbeApiError::TimedOut)?
}

/// Validate the final HTTP/1.x status line and display its standard status.
fn parse_http_status_line(response: &[u8]) -> Result<String, ProbeApiError> {
    let line = response
        .strip_suffix(b"\r\n")
        .ok_or(ProbeApiError::InvalidStatusLine)?;
    let mut fields = line.splitn(3, |byte| *byte == b' ');
    let version = match fields.next() {
        Some(b"HTTP/1.0") => "HTTP/1.0",
        Some(b"HTTP/1.1") => "HTTP/1.1",
        _ => return Err(ProbeApiError::InvalidStatusLine),
    };
    let code = fields.next().ok_or(ProbeApiError::InvalidStatusLine)?;
    let reason = fields.next().ok_or(ProbeApiError::InvalidStatusLine)?;

    if reason
        .iter()
        .any(|byte| *byte != b'\t' && byte.is_ascii_control())
    {
        return Err(ProbeApiError::InvalidStatusLine);
    }

    let status = StatusCode::from_bytes(code).map_err(ProbeApiError::StatusCode)?;

    if status.is_informational() || status.as_u16() > 599 {
        return Err(ProbeApiError::InvalidStatusLine);
    }

    let line = format!("{version} {status}");

    if status.is_server_error() {
        return Err(ProbeApiError::ServerFault { line });
    }

    Ok(line)
}

/// Check database, DNS listener, and secondary status through the daemon.
pub(crate) async fn check_services(report: &mut Report) {
    let doctor = match client::send_command::<DaemonDoctorResponse>(DaemonCommand::Doctor).await {
        Ok(response) => response.data,
        Err(error) => {
            report.fail(format!("Daemon-side checks failed: {}", error.message));
            return;
        }
    };

    let database_failed = doctor.database.status == DoctorCheckStatus::Failed;
    report.push(doctor.database);
    report.push(doctor.dns_server);

    if let Some(check) = doctor.dns_tls_server {
        report.push(check);
    }

    if database_failed {
        report.skip("Secondary checks skipped: the database did not answer");
        return;
    }
    if doctor.diagnostics.secondaries.is_empty() {
        report.skip("No enabled secondaries");
        return;
    }

    // These serials are the catalog zone's, unlike `zone status`, so say so.
    let catalog_zone_name = &doctor.catalog_zone_name;

    for secondary in &doctor.diagnostics.secondaries {
        let serial = secondary.visible_serial.map_or(0, Serial::as_u32);

        let line = match secondary.status {
            SecondaryStatus::InSync => format!(
                "Secondary {}: {} (catalog zone {catalog_zone_name} at serial {serial})",
                secondary.status, secondary.address
            ),
            // Answered, but its serial could not be compared with Bindizr's.
            SecondaryStatus::Reachable => format!(
                "Secondary {}: {} (catalog zone {catalog_zone_name} at serial {serial}; not compared with bindizr's)",
                secondary.status, secondary.address
            ),
            SecondaryStatus::Unreachable => format!(
                "Secondary {}: {} ({})",
                secondary.status,
                secondary.address,
                secondary.error.as_deref().unwrap_or("unknown error")
            ),
            SecondaryStatus::Lagging | SecondaryStatus::Ahead => format!(
                "Secondary {}: {} (catalog zone {catalog_zone_name} at serial {serial}; bindizr serves {})",
                secondary.status,
                secondary.address,
                doctor.catalog_serial.map_or(0, Serial::as_u32)
            ),
        };

        // The same verdict `secondary check` reaches: only a compared, equal serial passes.
        if secondary.is_in_sync() {
            report.ok(line);
        } else {
            report.fail(line);
        }
    }

    for notify in &doctor.diagnostics.notifies {
        match &notify.error {
            Some(error) => report.fail(format!("NOTIFY rejected: {} ({error})", notify.address)),
            None => report.ok(format!("NOTIFY accepted: {}", notify.address)),
        }
    }

    // What Bindizr served each secondary is information, not a verdict.
    for transfer in &doctor.diagnostics.transfers {
        let line = format!(
            "Transfers to {}: {}",
            transfer.address,
            output::display_transfer_summary(&transfer.summary)
        );

        if transfer.summary.zones == 0 {
            report.skip(line);
        } else {
            report.ok(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the probe checks framing and a valid status before reporting reachability.
    #[test]
    fn probe_requires_a_complete_http_status_line() {
        for malformed in [
            &b"HTTP/1.1"[..],
            b"HTTP/1.1 200 OK\n",
            b"HTTP/1.1 200\r\n",
            b"HTTP/1.1 20 OK\r\n",
            b"HTTP/1.1 100 Continue\r\n",
            b"HTTP/1.1 999 Invalid\r\n",
            b"HTTP/1.0 200 O\x00K\r\n",
            b"HTTP/2.0 200 OK\r\n",
        ] {
            assert!(parse_http_status_line(malformed).is_err(), "{malformed:?}");
        }

        assert_eq!(
            parse_http_status_line(b"HTTP/1.0 401 \r\n").unwrap(),
            "HTTP/1.0 401 Unauthorized"
        );
        assert!(matches!(
            parse_http_status_line(b"HTTP/1.1 503 Service Unavailable\r\n"),
            Err(ProbeApiError::ServerFault { line }) if line == "HTTP/1.1 503 Service Unavailable"
        ));
    }
}
