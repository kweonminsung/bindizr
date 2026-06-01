use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct CatalogZoneState {
    pub name: String,
    pub signature: String,
    pub serial: i32,
    pub updated_at: DateTime<Utc>,
}
