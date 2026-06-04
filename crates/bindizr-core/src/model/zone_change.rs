use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct ZoneChange {
    pub id: i32,
    pub zone_id: i32,
    pub serial: i32,
    pub operation: String, // "ADD" or "DEL"
    pub record_name: String,
    pub record_type: String,
    pub record_value: String,
    pub record_ttl: Option<i32>,
    pub record_priority: Option<i32>,
}
