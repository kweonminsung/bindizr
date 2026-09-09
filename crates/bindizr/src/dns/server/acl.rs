//! Access control for zone transfers: matches client addresses against the
//! configured secondary servers.

use std::net::IpAddr;

use bindizr_core::{
    config,
    dns::address::{ParsedAddress, parse_address_target},
    log_warn,
};
use tokio::net::lookup_host;

#[derive(Clone)]
pub(crate) struct SecondaryAcl {
    entries: Vec<SecondaryAclEntry>,
}

impl SecondaryAcl {
    pub(crate) fn from_config() -> Self {
        Self::parse(&config::bindizr_config().dns.secondary_addrs)
    }

    fn parse(raw: &str) -> Self {
        let entries = raw
            .split(',')
            .filter_map(|item| {
                let trimmed = item.trim();
                if trimmed.is_empty() {
                    return None;
                }

                match parse_address_target(trimmed, 53) {
                    ParsedAddress::SocketAddr(addr) => Some(SecondaryAclEntry::Ip(addr.ip())),
                    ParsedAddress::HostPort(host_port) => {
                        Some(SecondaryAclEntry::HostPort(host_port))
                    }
                }
            })
            .collect();
        Self { entries }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SecondaryAclEntry {
    Ip(IpAddr),
    HostPort(String),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secondary_acl_keeps_hostnames_for_runtime_resolution() {
        assert_eq!(
            SecondaryAcl::parse("192.0.2.10:53, bind9-0.bind9-headless:53").entries,
            vec![
                SecondaryAclEntry::Ip("192.0.2.10".parse().unwrap()),
                SecondaryAclEntry::HostPort("bind9-0.bind9-headless:53".to_string()),
            ]
        );
    }

    #[test]
    fn secondary_acl_defaults_hostname_ports() {
        assert_eq!(
            SecondaryAcl::parse("bind9-0.bind9-headless").entries,
            vec![SecondaryAclEntry::HostPort(
                "bind9-0.bind9-headless:53".to_string()
            )]
        );
    }
}
