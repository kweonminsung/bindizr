//! Parent-DS probing. The service decides when the parent is asked; the DNS
//! I/O is the binary's, injected like the NOTIFY sender.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use bindizr_core::dns::query::DsAnswer;

#[async_trait]
pub trait ParentDsProbe: Send + Sync {
    /// The zone's DS RRset as `dnssec.parent_ds_resolver` sees it.
    async fn probe_parent_ds(&self, zone_name: &str) -> Result<Vec<DsAnswer>, String>;
}

static PARENT_DS_PROBE: OnceLock<Arc<dyn ParentDsProbe>> = OnceLock::new();

/// Register the global parent-DS probe; fails if one is already registered.
pub fn set_parent_ds_probe(probe: Arc<dyn ParentDsProbe>) -> Result<(), &'static str> {
    PARENT_DS_PROBE
        .set(probe)
        .map_err(|_| "parent-DS probe is already registered")
}

/// Ask the configured resolver for `zone_name`'s DS RRset.
pub(crate) async fn probe_parent_ds(zone_name: &str) -> Result<Vec<DsAnswer>, String> {
    match PARENT_DS_PROBE.get() {
        Some(probe) => probe.probe_parent_ds(zone_name).await,
        None => Err("parent-DS probe is not registered".to_string()),
    }
}
