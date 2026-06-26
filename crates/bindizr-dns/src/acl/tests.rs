use super::*;

#[test]
fn secondary_acl_keeps_hostnames_for_runtime_resolution() {
    assert_eq!(
        parse_secondary_acl_entries("192.0.2.10:53, bind9-0.bind9-headless:53"),
        vec![
            SecondaryAclEntry::Ip("192.0.2.10".parse().unwrap()),
            SecondaryAclEntry::HostPort("bind9-0.bind9-headless:53".to_string()),
        ]
    );
}

#[test]
fn secondary_acl_defaults_hostname_ports() {
    assert_eq!(
        parse_secondary_acl_entries("bind9-0.bind9-headless"),
        vec![SecondaryAclEntry::HostPort(
            "bind9-0.bind9-headless:53".to_string()
        )]
    );
}
