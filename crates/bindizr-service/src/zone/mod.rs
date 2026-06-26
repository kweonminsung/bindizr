mod catalog_zone_state;
mod create;
mod delete;
mod force;
mod get;
pub mod snapshot;
mod update;
pub(crate) mod validation;

// Default SOA timing fields (seconds) applied when a request omits them.
pub(crate) const DEFAULT_REFRESH: i32 = 86_400;
pub(crate) const DEFAULT_RETRY: i32 = 7_200;
pub(crate) const DEFAULT_EXPIRE: i32 = 3_600_000;
pub(crate) const DEFAULT_MINIMUM_TTL: i32 = 86_400;

#[derive(Clone)]
pub struct ZoneService;
