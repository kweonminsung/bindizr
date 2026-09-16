use std::{fmt, io::ErrorKind, net::SocketAddr, path::Path, time::Duration};

use bindizr_core::config::{self, BindizrConfig, DatabaseType};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

use crate::{
    cli::{error::CliError, output::color},
    net::loopback_if_unspecified,
    socket::{
        client,
        types::{DaemonCommandKind, DaemonDoctorResponse},
    },
};

const API_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
/// A database that does not answer must become a failed check, not a hang.
const DB_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Tallies check outcomes so the exit code can reflect them.
struct Report {
    failures: usize,
}

impl Report {
    /// Print a successful diagnostic check.
    fn ok(&mut self, message: impl fmt::Display) {
        println!("[{}] {}", color::green("OK"), message);
    }

    /// Print a failed diagnostic check and increment the failure count.
    fn fail(&mut self, message: impl fmt::Display) {
        self.failures += 1;
        println!("[{}] {}", color::red("FAIL"), message);
    }

    /// Print a skipped diagnostic check.
    fn skip(&mut self, message: impl fmt::Display) {
        println!("[{}] {}", color::yellow("SKIP"), message);
    }
}

/// Handle the `doctor` subcommand by verifying the installation end to end.
pub(crate) async fn handle_command(config_file: Option<String>) -> Result<(), CliError> {
    println!("Bindizr Doctor");
    println!();

    let mut report = Report { failures: 0 };

    let path = config::resolve_config_path(config_file.as_deref());
    let file_config = match config::load_config_file(&path) {
        Ok(config) => {
            report.ok(format!("Config valid: {}", path));
            Some(config)
        }
        Err(e) => {
            report.fail(format!("Config invalid: {}", e));
            None
        }
    };
    if check_daemon(&mut report).await {
        match client::fetch_config().await {
            Ok(config) => check_api(&config, &mut report).await,
            Err(e) => report.fail(format!("Daemon config not readable: {}", e.message)),
        }
        check_daemon_side(&mut report).await;
    } else if let Some(config) = &file_config {
        // What a daemon that failed to start most likely hit.
        report.skip("API check skipped: daemon is not running");
        check_database_offline(config, &mut report).await;
        check_listen_ports(config, &mut report).await;
    } else {
        report.skip("API, database, and port checks skipped: no valid configuration");
    }
    check_bind_catalog(
        file_config.as_ref().map(|config| config.dns.listen_port),
        &mut report,
    );

    println!();
    if report.failures == 0 {
        println!("Result: installation looks {}", color::green("healthy"));
        Ok(())
    } else {
        Err(CliError::from(format!(
            "installation has {} failing check(s)",
            report.failures
        )))
    }
}

/// Connect to the configured database from here, with no daemon to ask.
async fn check_database_offline(config: &BindizrConfig, report: &mut Report) {
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
                "Database check skipped: SQLite file '{}' is created on first start",
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
async fn check_listen_ports(config: &BindizrConfig, report: &mut Report) {
    let dns = SocketAddr::new(config.dns.listen_addr, config.dns.listen_port);
    let bound = async {
        let _tcp = TcpListener::bind(dns).await?;
        let _udp = UdpSocket::bind(dns).await?;
        Ok::<(), std::io::Error>(())
    };
    match bound.await {
        Ok(()) => report.ok(format!("DNS port free: {}", dns)),
        Err(e) if e.kind() == ErrorKind::AddrInUse => report.fail(format!(
            "DNS port in use: {} (BIND on this host? change dns.listen_port)",
            dns
        )),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => report.skip(format!(
            "DNS port check skipped: binding {} needs root",
            dns
        )),
        Err(e) => report.fail(format!("DNS port not bindable: {} ({})", dns, e)),
    }

    let api = SocketAddr::new(config.api.listen_addr, config.api.listen_port);
    match TcpListener::bind(api).await {
        Ok(_) => report.ok(format!("API port free: {}", api)),
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            report.fail(format!("API port in use: {} (change api.listen_port)", api))
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => report.skip(format!(
            "API port check skipped: binding {} needs root",
            api
        )),
        Err(e) => report.fail(format!("API port not bindable: {} ({})", api, e)),
    }
}

/// Check this host's BIND configuration for the catalog zone and its port.
fn check_bind_catalog(listen_port: Option<u16>, report: &mut Report) {
    // The layout detection setup_bind.sh uses.
    let (main_conf, options_file) = if Path::new("/etc/bind").is_dir() {
        ("/etc/bind/named.conf", "/etc/bind/named.conf.options")
    } else if Path::new("/etc/named").is_dir() {
        ("/etc/named.conf", "/etc/named.conf")
    } else {
        report.skip("BIND check skipped: no BIND configuration on this host");
        return;
    };
    let (main, options) = match (
        std::fs::read_to_string(main_conf),
        std::fs::read_to_string(options_file),
    ) {
        (Ok(main), Ok(options)) => (main, options),
        (Err(e), _) | (_, Err(e)) => {
            report.skip(format!(
                "BIND check skipped: cannot read {} ({})",
                main_conf, e
            ));
            return;
        }
    };

    if !main.contains("zone \"catalog.bind\"") || !options.contains("catalog-zones") {
        report.fail(format!(
            "BIND catalog zone not configured in {}: run /usr/share/bindizr/setup_bind.sh",
            main_conf
        ));
        return;
    }
    match (primaries_port(&options), listen_port) {
        (Some(port), Some(expected)) if port != expected => report.fail(format!(
            "BIND fetches the catalog from port {} but bindizr listens on {}: rerun setup_bind.sh",
            port, expected
        )),
        (Some(port), _) => report.ok(format!(
            "BIND catalog zone configured: {} (primaries port {})",
            main_conf, port
        )),
        (None, _) => report.ok(format!("BIND catalog zone configured: {}", main_conf)),
    }
}

/// The port on the catalog zone's `default-primaries` line, if it names one.
fn primaries_port(options: &str) -> Option<u16> {
    let rest = &options[options.find("default-primaries")?..];
    let mut tokens = rest.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "port" {
            return tokens.next()?.trim_end_matches(';').parse().ok();
        }
        // No port before the list closed: BIND's default.
        if token.starts_with('}') {
            return Some(53);
        }
    }
    None
}

/// Check whether the daemon responds through its control socket.
async fn check_daemon(report: &mut Report) -> bool {
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
async fn check_api(config: &bindizr_core::config::BindizrConfig, report: &mut Report) {
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
async fn check_daemon_side(report: &mut Report) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the primaries port is read from both layouts and defaults to 53.
    #[test]
    fn primaries_port_reads_the_catalog_zone_line() {
        let one_line = "catalog-zones {\n    zone \"catalog.bind\" default-primaries { 127.0.0.1 port 5300; };\n};";
        assert_eq!(primaries_port(one_line), Some(5300));

        let nested = "catalog-zones {\n  zone \"catalog.bind\" {\n    default-primaries { 10.0.0.5 port 53; };\n  };\n};";
        assert_eq!(primaries_port(nested), Some(53));

        let no_port = "catalog-zones { zone \"catalog.bind\" default-primaries { 127.0.0.1; }; };";
        assert_eq!(primaries_port(no_port), Some(53));

        assert_eq!(primaries_port("options { };"), None);
    }
}
