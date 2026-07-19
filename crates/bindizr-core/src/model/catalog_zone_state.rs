use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// Tracked state of the BIND catalog zone used to detect changes.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CatalogZoneState {
    pub name: String,
    pub signature: String,
    pub serial: i32,
    pub updated_at: DateTime<Utc>,
}
