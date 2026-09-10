//! Access control for zone transfers: matches client addresses against the
//! configured secondary servers.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use bindizr_core::{
    config,
    dns::address::{ParsedAddress, parse_address_target},
    log_warn,
};
use tokio::{net::lookup_host, sync::Mutex as AsyncMutex, time::timeout};

/// How long a resolved hostname is reused; an address changes rarely.
const RESOLVED_TTL: Duration = Duration::from_secs(60);

/// Failures are remembered too, so a dead resolver costs one lookup per window.
const RESOLVE_FAILURE_TTL: Duration = Duration::from_secs(5);

/// A resolver that never answers must not hold a DNS request open.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

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

struct CachedAddrs {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

static RESOLVED: OnceLock<Mutex<HashMap<String, CachedAddrs>>> = OnceLock::new();

/// Held across a lookup so a cold cache costs one resolver request, not one per
/// waiting query. Entries are few, so one gate for all of them is enough.
static RESOLVING: OnceLock<AsyncMutex<()>> = OnceLock::new();

fn cached_addrs(host_port: &str) -> Option<Vec<IpAddr>> {
    locked_cache()
        .get(host_port)
        .filter(|cached| cached.expires_at > Instant::now())
        .map(|cached| cached.addrs.clone())
}

fn locked_cache() -> std::sync::MutexGuard<'static, HashMap<String, CachedAddrs>> {
    RESOLVED
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) async fn is_client_allowed(client_ip: IpAddr, acl: &SecondaryAcl) -> bool {
    // Literals first: a match there answers without reaching the resolver.
    if acl
        .entries
        .iter()
        .any(|entry| matches!(entry, SecondaryAclEntry::Ip(ip) if *ip == client_ip))
    {
        return true;
    }

    for entry in &acl.entries {
        if let SecondaryAclEntry::HostPort(host_port) = entry
            && resolve_acl_host(host_port).await.contains(&client_ip)
        {
            return true;
        }
    }

    false
}

async fn resolve_acl_host(host_port: &str) -> Vec<IpAddr> {
    if let Some(addrs) = cached_addrs(host_port) {
        return addrs;
    }

    let _resolving = RESOLVING.get_or_init(|| AsyncMutex::new(())).lock().await;

    // Another waiter may have filled the entry while this one queued.
    if let Some(addrs) = cached_addrs(host_port) {
        return addrs;
    }

    let (addrs, ttl) = match timeout(RESOLVE_TIMEOUT, lookup_host(host_port)).await {
        Ok(Ok(addrs)) => (
            addrs.map(|addr| addr.ip()).collect::<Vec<_>>(),
            RESOLVED_TTL,
        ),
        Ok(Err(e)) => {
            log_warn!("Failed to resolve DNS ACL host '{}': {}", host_port, e);
            (Vec::new(), RESOLVE_FAILURE_TTL)
        }
        Err(_) => {
            log_warn!(
                "Timed out resolving DNS ACL host '{}' after {:?}",
                host_port,
                RESOLVE_TIMEOUT
            );
            (Vec::new(), RESOLVE_FAILURE_TTL)
        }
    };

    locked_cache().insert(
        host_port.to_string(),
        CachedAddrs {
            addrs: addrs.clone(),
            expires_at: Instant::now() + ttl,
        },
    );
    addrs
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

    #[tokio::test]
    async fn literal_entries_answer_without_resolving() {
        // The unresolvable entry proves no lookup happened.
        let acl = SecondaryAcl::parse("192.0.2.10, no-such-host.invalid:53");

        assert!(is_client_allowed("192.0.2.10".parse().unwrap(), &acl).await);
        assert!(locked_cache().is_empty());
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
