//! This host's BIND configuration: the catalog zone and the port it is fetched from.

use std::path::Path;

use super::Report;

/// Check this host's BIND configuration for the catalog zone and its port.
pub(crate) fn check_catalog(listen_port: Option<u16>, report: &mut Report) {
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
