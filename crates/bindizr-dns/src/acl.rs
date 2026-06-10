use std::net::IpAddr;

use tokio::net::lookup_host;

use crate::{
    address::{ParsedAddress, parse_address_target},
    config, log_warn,
};

#[derive(Clone)]
pub(crate) struct SecondaryAcl {
    entries: Vec<SecondaryAclEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SecondaryAclEntry {
    Ip(IpAddr),
    HostPort(String),
}

pub(crate) fn secondary_acl_from_config() -> SecondaryAcl {
    SecondaryAcl {
        entries: parse_secondary_acl_entries(&config::get_bindizr_config().dns.secondary_addrs),
    }
}

pub(crate) async fn is_client_allowed(client_ip: IpAddr, acl: &SecondaryAcl) -> bool {
    for entry in &acl.entries {
        match entry {
            SecondaryAclEntry::Ip(ip) if *ip == client_ip => return true,
            SecondaryAclEntry::Ip(_) => {}
            SecondaryAclEntry::HostPort(host_port) => match lookup_host(host_port).await {
                Ok(addrs) => {
                    if addrs.into_iter().any(|addr| addr.ip() == client_ip) {
                        return true;
                    }
                }
                Err(e) => {
                    log_warn!("Failed to resolve DNS ACL host '{}': {}", host_port, e);
                }
            },
        }
    }

    false
}

fn parse_secondary_acl_entries(raw: &str) -> Vec<SecondaryAclEntry> {
    raw.split(',')
        .filter_map(|item| {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                return None;
            }

            match parse_address_target(trimmed, 53) {
                ParsedAddress::SocketAddr(addr) => Some(SecondaryAclEntry::Ip(addr.ip())),
                ParsedAddress::HostPort(host_port) => Some(SecondaryAclEntry::HostPort(host_port)),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
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
}
