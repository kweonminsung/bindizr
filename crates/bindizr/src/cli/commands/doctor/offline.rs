//! Checks run from this process when no daemon is up: the database and the
//! listen ports.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use bindizr_core::config::{Config, DatabaseType};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time;

use crate::cli::commands::doctor::Report;

/// A database that does not answer must become a failed check, not a hang;
/// longer than the daemon's probe budget since this connects from scratch.
const DB_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect to the configured database from here, with no daemon to ask.
pub(crate) async fn check_database(config: &Config, report: &mut Report) {
    let database = &config.database;

    if database.database_type == DatabaseType::Sqlite {
        let file_path = Path::new(&database.sqlite.file_path);

        // Only the service knows what a relative path resolves against.
        if !file_path.is_absolute() {
            report.skip(format!(
                "Database check skipped: SQLite path '{}' is relative to the service's working directory",
                database.sqlite.file_path
            ));
            return;
        }
        if !file_path.exists() {
            report.skip(format!(
                "Database check skipped: SQLite file '{}' is created on first start, with its directory",
                database.sqlite.file_path
            ));
            return;
        }
    }

    match time::timeout(DB_CHECK_TIMEOUT, bindizr_db::probe_connection(database)).await {
        Ok(Ok(())) => report.ok(format!("Database reachable: {}", database.database_type)),
        Ok(Err(error)) => report.fail(format!("Database not reachable: {error}")),
        Err(_) => report.fail(format!(
            "Database not reachable: timed out after {} seconds",
            DB_CHECK_TIMEOUT.as_secs()
        )),
    }
}

/// Try binding the DNS and API listen addresses.
pub(crate) async fn check_listen_ports(config: &Config, report: &mut Report) {
    let dns_addr = SocketAddr::new(config.dns.listen_addr, config.dns.listen_port);

    let bound = async {
        let _tcp = TcpListener::bind(dns_addr).await?;
        let _udp = UdpSocket::bind(dns_addr).await?;
        Ok::<(), io::Error>(())
    };
    check_port(
        report,
        "DNS",
        dns_addr,
        bound.await,
        "BIND on this host? change dns.listen_port",
    );

    if config.dns.tls.tls_files().is_some() {
        let dns_tls_addr = SocketAddr::new(config.dns.listen_addr, config.dns.tls.listen_port);

        let bound = TcpListener::bind(dns_tls_addr).await.map(|_| ());
        check_port(
            report,
            "DNS TLS",
            dns_tls_addr,
            bound,
            "change dns.tls.listen_port",
        );
    }

    let api_addr = SocketAddr::new(config.api.listen_addr, config.api.listen_port);

    let bound = TcpListener::bind(api_addr).await.map(|_| ());
    check_port(report, "API", api_addr, bound, "change api.listen_port");
}

/// Check one listen address by its bind result; a taken port carries `in_use_hint`.
fn check_port(
    report: &mut Report,
    label: &str,
    addr: SocketAddr,
    bound: io::Result<()>,
    in_use_hint: &str,
) {
    match bound {
        Ok(()) => report.ok(format!("{label} port free: {addr}")),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            report.fail(format!("{label} port in use: {addr} ({in_use_hint})"));
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => report.skip(format!(
            "{label} port check skipped: binding {addr} needs root"
        )),
        Err(error) => report.fail(format!("{label} port not bindable: {addr} ({error})")),
    }
}
