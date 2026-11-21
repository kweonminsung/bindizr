//! The SQLite SQL, one module per entity; the crate root dispatches here.

pub(crate) mod access_log;
pub(crate) mod api_token;
pub(crate) mod audit_log;
pub(crate) mod catalog_zone;
pub(crate) mod dnssec_key;
pub(crate) mod dnssec_policy;
pub(crate) mod dnssec_record;
pub(crate) mod dnssec_withdrawal;
pub(crate) mod path;
pub(crate) mod record;
pub(crate) mod role;
pub(crate) mod role_grant;
pub(crate) mod secondary;
pub(crate) mod transfer_log;
pub(crate) mod tsig_key;
pub(crate) mod zone;
pub(crate) mod zone_change;
pub(crate) mod zone_version;

use sqlx::error;
use sqlx::sqlite::SqliteQueryResult;

use crate::error::DatabaseError;

/// How long a connection waits for the database writer. Set before WAL locks
/// too: short timeouts starve BEGIN IMMEDIATE waiters into SQLITE_BUSY.
pub(crate) const BUSY_TIMEOUT_PRAGMA: &str = "PRAGMA busy_timeout = 15000";

/// SQLITE_BUSY, the primary result code of every busy extended code.
const SQLITE_BUSY: i32 = 5;

/// Return the id SQLite assigned the inserted row, refused rather than
/// truncated past `i32`.
pub(crate) fn last_insert_id(result: &SqliteQueryResult) -> Result<i32, DatabaseError> {
    let id = result.last_insert_rowid();
    i32::try_from(id).map_err(|_| DatabaseError::IdOutOfRange { id })
}

/// Return whether SQLite refused for want of the writer it would have waited for.
pub(crate) fn is_busy(error: &dyn error::DatabaseError) -> bool {
    error
        .code()
        .and_then(|code| code.parse::<i32>().ok())
        .is_some_and(|code| code & 0xff == SQLITE_BUSY)
}

#[cfg(test)]
mod tests;
