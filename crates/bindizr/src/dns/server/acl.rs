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
struct CachedAddrs {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

/// Hostname resolutions reused by secondary ACL checks until they expire.
#[derive(Debug, Default)]
pub(crate) struct AddressCache {
    cache: Mutex<HashMap<String, CachedAddrs>>,
}

impl AddressCache {
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
    Ok(allows_client(
        &dns_cx.address_cache,
        secondaries.iter().map(|secondary| &secondary.address),
        client_ip,
    )
    .await)
}

/// Match literal IPs first, then resolve hostnames through the ACL cache.
async fn allows_client<'a>(
    cache: &AddressCache,
    addresses: impl Iterator<Item = &'a AddressTarget> + Clone,
    client_ip: IpAddr,
) -> bool {
    if addresses
        .clone()
        .any(|address| matches!(address, AddressTarget::Socket(addr) if addr.ip() == client_ip))
    {
        return true;
    }

    for address in addresses {
        let AddressTarget::HostPort(host_port) = address else {
            continue;
        };
        let addrs = match cache.cached_addrs(host_port) {
            Some(addrs) => addrs,
            None => {
                let (addrs, ttl) = match resolve_address_entry(address, RESOLVE_TIMEOUT).await {
                    Ok(addrs) => (
                        addrs.into_iter().map(|addr| addr.ip()).collect::<Vec<_>>(),
                        RESOLVED_TTL,
                    ),
                    Err(_) => (Vec::new(), RESOLVE_FAILURE_TTL),
                };
                cache.locked().insert(
                    host_port.clone(),
                    CachedAddrs {
                        addrs: addrs.clone(),
                        expires_at: Instant::now() + ttl,
                    },
                );
                addrs
            }
        };
        if addrs.contains(&client_ip) {
            return true;
        }
    }
    false
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

    /// Match either IP family regardless of port, without resolving earlier hostnames.
    #[tokio::test]
    async fn literal_entries_answer_without_resolving() {
        let addresses = targets(&[
            "no-such-host.invalid:53",
            "192.0.2.10:5353",
            "[2001:db8::10]:853",
        ]);
        let cache = AddressCache::new();

        for ip in ["192.0.2.10", "2001:db8::10"] {
            assert!(allows_client(&cache, addresses.iter(), ip.parse().unwrap()).await);
        }
        assert!(cache.locked().is_empty());
    }

    /// Deny unmatched clients, including when the registry is empty.
    #[tokio::test]
    async fn only_configured_addresses_allow_clients() {
        let cache = AddressCache::new();
        let client_ip = "192.0.2.11".parse().unwrap();
        assert!(!allows_client(&cache, targets(&[]).iter(), client_ip).await);
        assert!(!allows_client(&cache, targets(&["192.0.2.10"]).iter(), client_ip).await);
    }

    /// Reuse successful and failed resolutions under the canonical hostname key.
    #[tokio::test]
    async fn hostname_entries_reuse_cached_resolutions() {
        let addresses = targets(&["Missing.Example.", "Bind9.Example."]);
        let cache = AddressCache::new();
        let client_ip = "192.0.2.10".parse().unwrap();
        let expires_at = Instant::now() + RESOLVED_TTL;
        cache.locked().extend([
            (
                "missing.example:53".to_string(),
                CachedAddrs {
                    addrs: Vec::new(),
                    expires_at,
                },
            ),
            (
                "bind9.example:53".to_string(),
                CachedAddrs {
                    addrs: vec![client_ip],
                    expires_at,
                },
            ),
        ]);

        assert!(allows_client(&cache, addresses.iter(), client_ip).await);
        assert!(!allows_client(&cache, addresses.iter(), "192.0.2.11".parse().unwrap()).await);
        assert_eq!(cache.locked()["missing.example:53"].expires_at, expires_at);
        assert_eq!(cache.locked()["bind9.example:53"].expires_at, expires_at);
    }
}
