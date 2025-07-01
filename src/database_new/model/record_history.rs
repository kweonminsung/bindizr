use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct RecordHistory {
    pub id: i32,
    pub log: String,
    pub created_at: String,
    pub record_id: i32,
}
