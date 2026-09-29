use std::time::Duration;

/// How long a front end waits for the database before answering without it;
/// a wedged database must not hang a probe, a scrape, `status`, or `doctor`.
pub(crate) const DB_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
