//! Access control for zone transfers: matches client addresses against the
//! enabled secondaries.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use bindizr_core::dns::address::{DEFAULT_DNS_PORT, ParsedAddress};
use bindizr_service::{
    dns_client::resolve_address_entry, error::ServiceError, secondary::SecondaryService,
};

/// How long a resolved hostname is reused; an address changes rarely.
const RESOLVED_TTL: Duration = Duration::from_secs(60);

/// Failures are remembered too, so a dead resolver costs one lookup per window.
const RESOLVE_FAILURE_TTL: Duration = Duration::from_secs(5);

/// A resolver that never answers must not hold a DNS request open.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

struct SecondaryAcl {
    entries: Vec<SecondaryAclEntry>,
}

impl SecondaryAcl {
    /// Check whether a peer IP is permitted by the secondary ACL.
    async fn allows(&self, client_ip: IpAddr) -> bool {
        // Literals first: a match there answers without reaching the resolver.
        if self
            .entries
            .iter()
            .any(|entry| matches!(entry, SecondaryAclEntry::Ip(ip) if *ip == client_ip))
        {
            return true;
        }

        for entry in &self.entries {
            if let SecondaryAclEntry::HostPort(host_port) = entry
                && resolve_acl_host(host_port).await.contains(&client_ip)
            {
                return true;
            }
        }

        false
    }

    /// The ACL the given `host[:port]` addresses name.
    fn from_addresses<'a>(addresses: impl IntoIterator<Item = &'a str>) -> Self {
        let entries = addresses
            .into_iter()
            .map(
                |address| match ParsedAddress::parse(address, DEFAULT_DNS_PORT) {
                    ParsedAddress::SocketAddr(addr) => SecondaryAclEntry::Ip(addr.ip()),
                    ParsedAddress::HostPort(host_port) => SecondaryAclEntry::HostPort(host_port),
                },
            )
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

/// Return cached address resolutions for an ACL hostname.
fn cached_addrs(host_port: &str) -> Option<Vec<IpAddr>> {
    locked_cache()
        .get(host_port)
        .filter(|cached| cached.expires_at > Instant::now())
        .map(|cached| cached.addrs.clone())
}

/// Lock the shared hostname resolution cache.
fn locked_cache() -> std::sync::MutexGuard<'static, HashMap<String, CachedAddrs>> {
    RESOLVED
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Whether `client_ip` is one of the enabled secondaries. The list is read
/// per check rather than captured at startup, so a change takes effect on
/// the next transfer; parsing a short list costs nothing next to the
/// hostname resolution it may avoid.
pub(crate) async fn is_client_allowed(client_ip: IpAddr) -> Result<bool, ServiceError> {
    let secondaries = SecondaryService::list_enabled().await?;
    let acl = SecondaryAcl::from_addresses(secondaries.iter().map(|s| s.address.as_str()));
    Ok(acl.allows(client_ip).await)
}

/// Resolve an ACL hostname to its permitted IP addresses. The resolver logs
/// a failure itself; here it only shortens how long the empty answer is kept.
async fn resolve_acl_host(host_port: &str) -> Vec<IpAddr> {
    if let Some(addrs) = cached_addrs(host_port) {
        return addrs;
    }

    let (addrs, ttl) = match resolve_address_entry(host_port, RESOLVE_TIMEOUT).await {
        Ok(addrs) => (
            addrs.into_iter().map(|addr| addr.ip()).collect::<Vec<_>>(),
            RESOLVED_TTL,
        ),
        Err(_) => (Vec::new(), RESOLVE_FAILURE_TTL),
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

    /// Verify that secondary acl keeps hostnames for runtime resolution.
    #[test]
    fn secondary_acl_keeps_hostnames_for_runtime_resolution() {
        assert_eq!(
            SecondaryAcl::from_addresses(["192.0.2.10:53", "bind9-0.bind9-headless:53"]).entries,
            vec![
                SecondaryAclEntry::Ip("192.0.2.10".parse().unwrap()),
                SecondaryAclEntry::HostPort("bind9-0.bind9-headless:53".to_string()),
            ]
        );
    }

    /// Verify that literal entries answer without resolving.
    #[tokio::test]
    async fn literal_entries_answer_without_resolving() {
        // The unresolvable entry proves no lookup happened.
        let acl = SecondaryAcl::from_addresses(["192.0.2.10", "no-such-host.invalid:53"]);

        assert!(acl.allows("192.0.2.10".parse().unwrap()).await);
        assert!(locked_cache().is_empty());
    }

    /// Verify that secondary acl defaults hostname ports.
    #[test]
    fn secondary_acl_defaults_hostname_ports() {
        assert_eq!(
            SecondaryAcl::from_addresses(["bind9-0.bind9-headless"]).entries,
            vec![SecondaryAclEntry::HostPort(
                "bind9-0.bind9-headless:53".to_string()
            )]
        );
    }
}
