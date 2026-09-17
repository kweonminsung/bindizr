//! Checks run from this process when no daemon is up: the database and the
//! listen ports.

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    path::Path,
    time::Duration,
};

use bindizr_core::config::{BindizrConfig, DatabaseType};
use tokio::net::{TcpListener, UdpSocket};

use super::Report;

/// A database that does not answer must become a failed check, not a hang.
const DB_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect to the configured database from here, with no daemon to ask.
pub(crate) async fn check_database(config: &BindizrConfig, report: &mut Report) {
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

    match tokio::time::timeout(DB_CHECK_TIMEOUT, bindizr_db::probe_connection(database)).await {
        Ok(Ok(())) => report.ok(format!("Database reachable: {}", database.database_type)),
        Ok(Err(e)) => report.fail(format!("Database not reachable: {}", e)),
        Err(_) => report.fail(format!(
            "Database not reachable: timed out after {} seconds",
            DB_CHECK_TIMEOUT.as_secs()
        )),
    }
}

/// Try binding the DNS and API listen addresses.
pub(crate) async fn check_listen_ports(config: &BindizrConfig, report: &mut Report) {
    let dns = SocketAddr::new(config.dns.listen_addr, config.dns.listen_port);
    let bound = async {
        let _tcp = TcpListener::bind(dns).await?;
        let _udp = UdpSocket::bind(dns).await?;
        Ok::<(), io::Error>(())
    };
    report_port(
        report,
        "DNS",
        dns,
        bound.await,
        "BIND on this host? change dns.listen_port",
    );

    let api = SocketAddr::new(config.api.listen_addr, config.api.listen_port);
    let bound = TcpListener::bind(api).await.map(|_| ());
    report_port(report, "API", api, bound, "change api.listen_port");
}

/// Report one listen address by its bind result; a taken port carries `in_use_hint`.
fn report_port(
    report: &mut Report,
    label: &str,
    addr: SocketAddr,
    bound: io::Result<()>,
    in_use_hint: &str,
) {
    match bound {
        Ok(()) => report.ok(format!("{} port free: {}", label, addr)),
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            report.fail(format!("{} port in use: {} ({})", label, addr, in_use_hint))
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => report.skip(format!(
            "{} port check skipped: binding {} needs root",
            label, addr
        )),
        Err(e) => report.fail(format!("{} port not bindable: {} ({})", label, addr, e)),
    }
}
