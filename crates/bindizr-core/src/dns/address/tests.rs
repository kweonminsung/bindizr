use super::*;

/// Render a parsed address with its variant so identical text cannot hide a
/// SocketAddr/HostPort mismatch.
fn target_to_string(target: AddressTarget) -> String {
    match target {
        AddressTarget::Socket(addr) => format!("SocketAddr({addr})"),
        AddressTarget::HostPort(host_port) => format!("HostPort({host_port})"),
    }
}

/// Verify that `AddressTarget::parse` defaults plain ip addresses to default port.
#[test]
fn parse_address_target_defaults_plain_ip_addresses_to_default_port() {
    assert_eq!(
        target_to_string(AddressTarget::parse("192.0.2.10", 53)),
        "SocketAddr(192.0.2.10:53)"
    );
    assert_eq!(
        target_to_string(AddressTarget::parse("2001:db8::1", 53)),
        "SocketAddr([2001:db8::1]:53)"
    );
    assert_eq!(
        target_to_string(AddressTarget::parse("[2001:db8::1]", 53)),
        "SocketAddr([2001:db8::1]:53)"
    );
}

/// Verify that `AddressTarget::parse` preserves explicit ports.
#[test]
fn parse_address_target_preserves_explicit_ports() {
    assert_eq!(
        target_to_string(AddressTarget::parse("192.0.2.10:5353", 53)),
        "SocketAddr(192.0.2.10:5353)"
    );
    assert_eq!(
        target_to_string(AddressTarget::parse("[2001:db8::1]:5353", 53)),
        "SocketAddr([2001:db8::1]:5353)"
    );
    assert_eq!(
        target_to_string(AddressTarget::parse("ns2.example.com:5353", 53)),
        "HostPort(ns2.example.com:5353)"
    );
}

/// Verify that `AddressTarget::parse` drops a hostname's trailing root dot.
#[test]
fn parse_drops_a_hostnames_trailing_root_dot() {
    assert_eq!(
        target_to_string(AddressTarget::parse("ns2.example.com.", 53)),
        "HostPort(ns2.example.com:53)"
    );
    assert_eq!(
        target_to_string(AddressTarget::parse("ns2.example.com.:5353", 53)),
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

/// Verify that `AddressTarget::parse` defaults hostname to default port.
#[test]
fn parse_address_target_defaults_hostname_to_default_port() {
    assert_eq!(
        target_to_string(AddressTarget::parse("ns2.example.com", 53)),
        "HostPort(ns2.example.com:53)"
    );
}
