//! Parsing of `host[:port]` address targets into socket addresses or deferred
//! host/port pairs.

use std::net::{IpAddr, SocketAddr};

use super::name::{MAX_DOMAIN_LEN, classify_domain_label};

pub enum ParsedAddress {
    SocketAddr(SocketAddr),
    HostPort(String),
}

pub fn parse_address_target(value: &str, default_port: u16) -> ParsedAddress {
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

fn is_hostname(value: &str) -> bool {
    let name = value.strip_suffix('.').unwrap_or(value);
    !name.is_empty()
        && name.len() <= MAX_DOMAIN_LEN
        && name
            .split('.')
            .all(|label| classify_domain_label(label, true).is_ok())
}

fn has_explicit_port(value: &str) -> bool {
    if let Some((_, rest)) = value.strip_prefix('[').and_then(|v| v.split_once(']')) {
        return rest.strip_prefix(':').is_some_and(is_valid_port);
    }

    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => is_valid_port(port),
        _ => false,
    }
}

fn is_valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tag the variant alongside the rendered value so a SocketAddr/HostPort
    // regression cannot slip through when both render to the same string.
    fn target_to_string(target: ParsedAddress) -> String {
        match target {
            ParsedAddress::SocketAddr(addr) => format!("SocketAddr({addr})"),
            ParsedAddress::HostPort(host_port) => format!("HostPort({host_port})"),
        }
    }

    #[test]
    fn parse_address_target_defaults_plain_ip_addresses_to_default_port() {
        assert_eq!(
            target_to_string(parse_address_target("192.0.2.10", 53)),
            "SocketAddr(192.0.2.10:53)"
        );
        assert_eq!(
            target_to_string(parse_address_target("2001:db8::1", 53)),
            "SocketAddr([2001:db8::1]:53)"
        );
        assert_eq!(
            target_to_string(parse_address_target("[2001:db8::1]", 53)),
            "SocketAddr([2001:db8::1]:53)"
        );
    }

    #[test]
    fn parse_address_target_preserves_explicit_ports() {
        assert_eq!(
            target_to_string(parse_address_target("192.0.2.10:5353", 53)),
            "SocketAddr(192.0.2.10:5353)"
        );
        assert_eq!(
            target_to_string(parse_address_target("[2001:db8::1]:5353", 53)),
            "SocketAddr([2001:db8::1]:5353)"
        );
        assert_eq!(
            target_to_string(parse_address_target("ns2.example.com:5353", 53)),
            "HostPort(ns2.example.com:5353)"
        );
    }

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

    #[test]
    fn parse_address_target_defaults_hostname_to_default_port() {
        assert_eq!(
            target_to_string(parse_address_target("ns2.example.com", 53)),
            "HostPort(ns2.example.com:53)"
        );
    }
}
