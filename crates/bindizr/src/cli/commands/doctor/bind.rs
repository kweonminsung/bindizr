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
    // The zone block fetches the catalog itself; `default-primaries` only
    // reaches the member zones it names. setup_bind.sh leaves a catalog zone
    // it did not write alone, so either port can go stale on its own.
    let ports = [
        ("the catalog zone", catalog_zone_port(&main)),
        ("its member zones", default_primaries_port(&options)),
    ];
    let stale: Vec<String> = ports
        .iter()
        .filter_map(|(what, port)| match (port, listen_port) {
            (Some(port), Some(expected)) if *port != expected => {
                Some(format!("{} from port {}", what, port))
            }
            _ => None,
        })
        .collect();
    if let (false, Some(expected)) = (stale.is_empty(), listen_port) {
        report.fail(format!(
            "BIND fetches {} but bindizr listens on {}: rerun setup_bind.sh",
            stale.join(" and "),
            expected
        ));
        return;
    }
    match ports.iter().filter_map(|(_, port)| *port).min() {
        Some(port) => report.ok(format!(
            "BIND catalog zone configured: {} (primaries port {})",
            main_conf, port
        )),
        None => report.ok(format!("BIND catalog zone configured: {}", main_conf)),
    }
}

/// The port named after `directive`, or BIND's default when the address list
/// closes without one.
fn port_after(text: &str, directive: &str) -> Option<u16> {
    let start = text.find(directive)? + directive.len();
    let mut tokens = text[start..].split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "port" {
            return tokens.next()?.trim_end_matches(';').parse().ok();
        }
        if token.starts_with('}') {
            return Some(53);
        }
    }
    None
}

/// The port the catalog's member zones are fetched from.
fn default_primaries_port(options: &str) -> Option<u16> {
    port_after(options, "default-primaries")
}

/// The port the catalog zone itself is fetched from, on the `primaries` line
/// of its own zone block.
fn catalog_zone_port(main: &str) -> Option<u16> {
    // The options stanza names the same zone without a block of its own, so
    // the brace is what tells the two apart.
    let mut rest = main;
    loop {
        let at = rest.find("zone \"catalog.bind\"")?;
        let block = &rest[at..];
        let body = block["zone \"catalog.bind\"".len()..].trim_start();
        if body.starts_with('{') {
            let end = body.find("\n};").map_or(body.len(), |i| i + 3);
            return port_after(&body[..end], "primaries");
        }
        rest = &rest[at + 1..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the member-zone port is read from both layouts and defaults to 53.
    #[test]
    fn default_primaries_port_reads_the_catalog_zone_line() {
        let one_line = "catalog-zones {\n    zone \"catalog.bind\" default-primaries { 127.0.0.1 port 5300; };\n};";
        assert_eq!(default_primaries_port(one_line), Some(5300));

        let nested = "catalog-zones {\n  zone \"catalog.bind\" {\n    default-primaries { 10.0.0.5 port 53; };\n  };\n};";
        assert_eq!(default_primaries_port(nested), Some(53));

        let no_port = "catalog-zones { zone \"catalog.bind\" default-primaries { 127.0.0.1; }; };";
        assert_eq!(default_primaries_port(no_port), Some(53));

        assert_eq!(default_primaries_port("options { };"), None);
    }

    /// Verify that the catalog's own port comes from its zone block.
    #[test]
    fn catalog_zone_port_reads_the_zone_block_not_the_options_stanza() {
        // The single-file layout holds both, and only the block fetches the
        // catalog itself, so the options stanza must not answer for it.
        let both = concat!(
            "options {\n    catalog-zones {\n",
            "        zone \"catalog.bind\" default-primaries { 127.0.0.1 port 5300; };\n",
            "    };\n};\n\n",
            "zone \"catalog.bind\" {\n    type secondary;\n",
            "    primaries { 127.0.0.1 port 5301; };\n};\n"
        );
        assert_eq!(catalog_zone_port(both), Some(5301));
        assert_eq!(default_primaries_port(both), Some(5300));

        assert_eq!(catalog_zone_port("options { };"), None);
    }
}
