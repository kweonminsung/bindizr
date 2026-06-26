use super::*;

fn target_to_string(target: ParsedAddress) -> String {
    match target {
        ParsedAddress::SocketAddr(addr) => addr.to_string(),
        ParsedAddress::HostPort(host_port) => host_port,
    }
}

#[test]
fn parse_address_target_defaults_plain_ip_addresses_to_default_port() {
    assert_eq!(
        target_to_string(parse_address_target("192.0.2.10", 53)),
        "192.0.2.10:53"
    );
    assert_eq!(
        target_to_string(parse_address_target("2001:db8::1", 53)),
        "[2001:db8::1]:53"
    );
    assert_eq!(
        target_to_string(parse_address_target("[2001:db8::1]", 53)),
        "[2001:db8::1]:53"
    );
}

#[test]
fn parse_address_target_preserves_explicit_ports() {
    assert_eq!(
        target_to_string(parse_address_target("192.0.2.10:5353", 53)),
        "192.0.2.10:5353"
    );
    assert_eq!(
        target_to_string(parse_address_target("[2001:db8::1]:5353", 53)),
        "[2001:db8::1]:5353"
    );
    assert_eq!(
        target_to_string(parse_address_target("ns2.example.com:5353", 53)),
        "ns2.example.com:5353"
    );
}

#[test]
fn parse_address_target_defaults_hostname_to_default_port() {
    assert_eq!(
        target_to_string(parse_address_target("ns2.example.com", 53)),
        "ns2.example.com:53"
    );
}
