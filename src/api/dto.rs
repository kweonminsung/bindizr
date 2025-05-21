use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateRecordRequest {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: i32,
    pub priority: Option<i32>,
    pub zone_id: i32,
}
