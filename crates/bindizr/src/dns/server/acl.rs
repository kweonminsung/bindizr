//! Access control for zone transfers: matches client addresses against the
//! enabled secondaries.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use bindizr_core::dns::address::AddressTarget;
use bindizr_service::{dns_client::resolve_address_entry, error::ServiceError, secondary};

use super::DnsContext;

/// How long a resolved hostname is reused; an address changes rarely.
const RESOLVED_TTL: Duration = Duration::from_secs(60);

/// Failures are remembered too, so a dead resolver costs one lookup per window.
const RESOLVE_FAILURE_TTL: Duration = Duration::from_secs(5);

/// A resolver that never answers must not hold a DNS request open.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecondaryAcl {
    entries: Vec<SecondaryAclEntry>,
}

impl SecondaryAcl {
    /// Check whether a peer IP is permitted by the secondary ACL.
    async fn allows(&self, resolved: &ResolvedAddrs, client_ip: IpAddr) -> bool {
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
                && resolve_acl_host(resolved, host_port)
                    .await
                    .contains(&client_ip)
            {
                return true;
            }
        }

        false
    }

    /// The ACL the given address targets name.
    fn from_addresses<'a>(addresses: impl IntoIterator<Item = &'a AddressTarget>) -> Self {
        let entries = addresses
            .into_iter()
            .map(|address| match address {
                AddressTarget::Socket(addr) => SecondaryAclEntry::Ip(addr.ip()),
                AddressTarget::HostPort(host_port) => {
                    SecondaryAclEntry::HostPort(host_port.clone())
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedAddrs {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

/// The hostnames the ACL resolved lately, so a transfer request waits on the
/// resolver once per window rather than once per query.
#[derive(Debug, Default)]
pub(crate) struct ResolvedAddrs {
    cache: Mutex<HashMap<String, CachedAddrs>>,
}

impl ResolvedAddrs {
    /// An empty resolution cache.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Return cached address resolutions for an ACL hostname.
    fn cached_addrs(&self, host_port: &str) -> Option<Vec<IpAddr>> {
        self.locked()
            .get(host_port)
            .filter(|cached| cached.expires_at > Instant::now())
            .map(|cached| cached.addrs.clone())
    }

    /// Lock the resolution cache, recovering a poisoned lock because a panic
    /// cannot leave a map of addresses inconsistent.
    fn locked(&self) -> MutexGuard<'_, HashMap<String, CachedAddrs>> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Check enabled secondary addresses afresh so changes affect the next transfer.
/// A direct IP match avoids hostname resolution.
pub(crate) async fn is_client_allowed(
    dns_cx: &DnsContext,
    client_ip: IpAddr,
) -> Result<bool, ServiceError> {
    let secondaries = secondary::list_enabled(dns_cx.daemon()).await?;
    let acl = SecondaryAcl::from_addresses(secondaries.iter().map(|s| &s.address));
    Ok(acl.allows(&dns_cx.acl, client_ip).await)
}

/// Resolve an ACL hostname to its permitted IP addresses. The resolver logs
/// a failure itself; here it only shortens how long the empty answer is kept.
async fn resolve_acl_host(resolved: &ResolvedAddrs, host_port: &str) -> Vec<IpAddr> {
    if let Some(addrs) = resolved.cached_addrs(host_port) {
        return addrs;
    }

    let target = AddressTarget::HostPort(host_port.to_string());
    let (addrs, ttl) = match resolve_address_entry(&target, RESOLVE_TIMEOUT).await {
        Ok(addrs) => (
            addrs.into_iter().map(|addr| addr.ip()).collect::<Vec<_>>(),
            RESOLVED_TTL,
        ),
        Err(_) => (Vec::new(), RESOLVE_FAILURE_TTL),
    };

    resolved.locked().insert(
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
    use bindizr_core::dns::address::DEFAULT_DNS_PORT;

    use super::*;

    /// Parse address targets as the service stores them.
    fn targets(values: &[&str]) -> Vec<AddressTarget> {
        values
            .iter()
            .map(|value| AddressTarget::parse(value, DEFAULT_DNS_PORT))
            .collect()
    }

    /// Verify that secondary acl keeps hostnames for runtime resolution.
    #[test]
    fn secondary_acl_keeps_hostnames_for_runtime_resolution() {
        assert_eq!(
            SecondaryAcl::from_addresses(&targets(&["192.0.2.10:53", "bind9-0.bind9-headless:53"]))
                .entries,
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
        let acl =
            SecondaryAcl::from_addresses(&targets(&["192.0.2.10", "no-such-host.invalid:53"]));
        let resolved = ResolvedAddrs::new();

        assert!(acl.allows(&resolved, "192.0.2.10".parse().unwrap()).await);
        assert!(resolved.locked().is_empty());
    }

    /// Verify that secondary acl defaults hostname ports.
    #[test]
    fn secondary_acl_defaults_hostname_ports() {
        assert_eq!(
            SecondaryAcl::from_addresses(&targets(&["bind9-0.bind9-headless"])).entries,
            vec![SecondaryAclEntry::HostPort(
                "bind9-0.bind9-headless:53".to_string()
            )]
        );
    }
}
