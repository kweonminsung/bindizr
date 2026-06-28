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
fn parse_address_target_defaults_hostname_to_default_port() {
    assert_eq!(
        target_to_string(parse_address_target("ns2.example.com", 53)),
        "HostPort(ns2.example.com:53)"
    );
}
