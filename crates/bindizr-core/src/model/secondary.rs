use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// A secondary server: it receives NOTIFY, may pull zones unsigned from its
/// address, and is probed for the serial it serves.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Secondary {
    pub id: i32,
    pub name: String,
    /// `host[:port]`; a hostname is resolved when used, not when stored.
    pub address: String,
    /// Disabled: no NOTIFY, no unsigned transfer, no probe; still registered.
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}
