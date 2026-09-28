use std::sync::OnceLock;

use chrono::{DateTime, Utc};

/// Set once by `bootstrap`, when every front end is up.
static STARTED_AT: OnceLock<DateTime<Utc>> = OnceLock::new();

/// Set the moment the daemon began serving; the first call wins.
pub(crate) fn set(at: DateTime<Utc>) {
    let _ = STARTED_AT.set(at);
}

/// The moment the daemon began serving, absent while it is still starting.
pub(crate) fn started_at() -> Option<DateTime<Utc>> {
    STARTED_AT.get().copied()
}
