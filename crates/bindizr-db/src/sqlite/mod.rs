//! The Sqlite SQL, one module per entity; the crate root dispatches here.

use sqlx::sqlite::SqliteQueryResult;

use crate::error::DatabaseError;

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
pub(crate) mod transfer;
pub(crate) mod tsig_key;
pub(crate) mod zone;
pub(crate) mod zone_change;
pub(crate) mod zone_version;

#[cfg(test)]
mod tests;

/// The id SQLite assigned the inserted row, refused rather than truncated past `i32`.
pub(crate) fn last_insert_id(result: &SqliteQueryResult) -> Result<i32, DatabaseError> {
    let id = result.last_insert_rowid();
    i32::try_from(id).map_err(|_| DatabaseError::IdOutOfRange { id })
}
