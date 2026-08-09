use crate::model::{record::RecordType, zone::Zone};

mod catalog_zone_state;
mod create;
mod delete;
mod export;
mod force;
mod get;
pub mod history;
mod notify;
mod snapshot;
pub mod token_policy;
pub mod tsig_policy;
mod update;
pub(crate) mod validation;

// Default SOA timing fields (seconds) applied when a request omits them.
// Bindizr drives propagation with NOTIFY, so keep refresh/retry short: they
// only bound how long a secondary stays stale if a (UDP) NOTIFY is ever lost,
// not the happy-path latency.
pub(crate) const DEFAULT_REFRESH: i32 = 300;
pub(crate) const DEFAULT_RETRY: i32 = 60;
pub(crate) const DEFAULT_EXPIRE: i32 = 3_600_000;
pub(crate) const DEFAULT_MINIMUM_TTL: i32 = 86_400;

/// TTL a synthesized apex NS must take to join the existing RRset rather than
/// split it (RFC 2181, Section 5.2). `candidates` are scanned in priority order,
/// falling back to the zone TTL.
pub(super) fn apex_ns_rrset_ttl<'a>(
    zone: &Zone,
    candidates: impl IntoIterator<Item = (&'a RecordType, &'a str, i32)>,
) -> i32 {
    candidates
        .into_iter()
        .find(|(record_type, name, _)| zone.is_apex_ns(record_type, name))
        .map_or(zone.ttl, |(_, _, ttl)| ttl)
}

/// Business logic for creating, updating, and querying DNS zones.
#[derive(Clone)]
pub struct ZoneService;

#[cfg(test)]
mod tests;
