//! Parsing of `host[:port]` address targets into socket addresses or deferred
//! host/port pairs.

use std::net::{IpAddr, SocketAddr};

use super::name::{MAX_DOMAIN_LEN, classify_domain_label};

/// An address target: a socket address, or a host and port to resolve later.
pub enum ParsedAddress {
    SocketAddr(SocketAddr),
    HostPort(String),
}

impl ParsedAddress {
    /// Parse an address target and supply the default port when needed.
    pub fn parse(value: &str, default_port: u16) -> Self {
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return ParsedAddress::SocketAddr(addr);
        }

        if let Ok(ip) = value.parse::<IpAddr>() {
            return ParsedAddress::SocketAddr(SocketAddr::new(ip, default_port));
        }

        if let Some(bracketed) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']'))
            && let Ok(ip) = bracketed.parse::<IpAddr>()
        {
            return ParsedAddress::SocketAddr(SocketAddr::new(ip, default_port));
        }

        let host_port = if has_explicit_port(value) || value.contains(':') {
            value.to_string()
        } else {
            format!("{}:{}", value, default_port)
        };

        ParsedAddress::HostPort(host_port)
    }
}

/// `host[:port]`, `ip[:port]`, or `[ipv6][:port]`: LDH labels (`_` allowed)
/// and a numeric, non-zero port, as the resolver takes them.
pub fn is_address_target(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return addr.port() != 0;
    }
    if let Some((ip, rest)) = value.strip_prefix('[').and_then(|v| v.split_once(']')) {
        return ip.parse::<IpAddr>().is_ok() && (rest.is_empty() || has_explicit_port(value));
    }
    match value.rsplit_once(':') {
        Some((host, _)) => has_explicit_port(value) && is_hostname(host),
        None => is_hostname(value),
    }
}

/// Check whether a hostname uses valid domain labels. A resolver target is an
/// LDH name with no escapes, so the dot is always a label boundary here.
fn is_hostname(value: &str) -> bool {
    let name = value.strip_suffix('.').unwrap_or(value);
    !name.is_empty()
        && name.len() <= MAX_DOMAIN_LEN
        && name
            .split('.')
            .all(|label| classify_domain_label(label, true).is_ok())
}

/// Check whether an address target includes a valid explicit port.
fn has_explicit_port(value: &str) -> bool {
    if let Some((_, rest)) = value.strip_prefix('[').and_then(|v| v.split_once(']')) {
        return rest.strip_prefix(':').is_some_and(is_valid_port);
    }

    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => is_valid_port(port),
        _ => false,
    }
}

/// Check whether text represents a nonzero 16-bit port.
fn is_valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render a parsed address with its variant so identical text cannot hide a
    /// SocketAddr/HostPort mismatch.
    fn target_to_string(target: ParsedAddress) -> String {
        match target {
            ParsedAddress::SocketAddr(addr) => format!("SocketAddr({addr})"),
            ParsedAddress::HostPort(host_port) => format!("HostPort({host_port})"),
        }
    }

    /// Verify that `ParsedAddress::parse` defaults plain ip addresses to default port.
    #[test]
    fn parse_address_target_defaults_plain_ip_addresses_to_default_port() {
        assert_eq!(
            target_to_string(ParsedAddress::parse("192.0.2.10", 53)),
            "SocketAddr(192.0.2.10:53)"
        );
        assert_eq!(
            target_to_string(ParsedAddress::parse("2001:db8::1", 53)),
            "SocketAddr([2001:db8::1]:53)"
        );
        assert_eq!(
            target_to_string(ParsedAddress::parse("[2001:db8::1]", 53)),
            "SocketAddr([2001:db8::1]:53)"
        );
    }

    /// Verify that `ParsedAddress::parse` preserves explicit ports.
    #[test]
    fn parse_address_target_preserves_explicit_ports() {
        assert_eq!(
            target_to_string(ParsedAddress::parse("192.0.2.10:5353", 53)),
            "SocketAddr(192.0.2.10:5353)"
        );
        assert_eq!(
            target_to_string(ParsedAddress::parse("[2001:db8::1]:5353", 53)),
            "SocketAddr([2001:db8::1]:5353)"
        );
        assert_eq!(
            target_to_string(ParsedAddress::parse("ns2.example.com:5353", 53)),
            "HostPort(ns2.example.com:5353)"
        );
    }

    /// Verify that `is_address_target` accepts host port forms and rejects the rest.
    #[test]
    fn is_address_target_accepts_host_port_forms_and_rejects_the_rest() {
        for value in [
            "ns.parent.example",
            "ns.parent.example.",
            "ns_1.parent.example:5353",
            "ns.parent.example:5353",
            "192.0.2.1",
            "192.0.2.1:53",
            "2001:db8::1",
            "[2001:db8::1]",
            "[2001:db8::1]:53",
        ] {
            assert!(is_address_target(value), "{value}");
        }
        for value in [
            "",
            "bad/name",
            "bad#name:53",
            "-bad.example",
            "ns.parent.example:not-a-port",
            "ns.parent.example:",
            "ns.parent.example:0",
            "192.0.2.1:0",
            "[2001:db8::1]:0",
            ":53",
            "[2001:db8::1",
            "[2001:db8::1]:x",
        ] {
            assert!(!is_address_target(value), "{value}");
        }
    }

    /// Verify that `ParsedAddress::parse` defaults hostname to default port.
    #[test]
    fn parse_address_target_defaults_hostname_to_default_port() {
        assert_eq!(
            target_to_string(ParsedAddress::parse("ns2.example.com", 53)),
            "HostPort(ns2.example.com:53)"
        );
    }
}
