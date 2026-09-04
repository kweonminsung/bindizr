mod catalog_zone_state;
mod create;
mod delete;
pub(crate) mod diff;
mod export;
mod force;
mod get;
pub(crate) mod history;
mod notify;
mod status;
pub mod token_policy;
pub mod tsig_policy;
mod update;
pub(crate) mod validation;
mod version;

// Seconds. Bindizr drives propagation with NOTIFY, so refresh/retry stay short:
// they only bound how long a secondary stays stale if a (UDP) NOTIFY is lost,
// not the happy-path latency.
pub(crate) const DEFAULT_REFRESH: i32 = 300;
pub(crate) const DEFAULT_RETRY: i32 = 60;
pub(crate) const DEFAULT_EXPIRE: i32 = 3_600_000;
pub(crate) const DEFAULT_MINIMUM_TTL: i32 = 86_400;

/// Business logic for creating, updating, and querying DNS zones.
#[derive(Clone)]
pub struct ZoneService;
