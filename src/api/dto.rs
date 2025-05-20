use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateRecordRequest {
    name: String,
    record_type: String,
    value: String,
    ttl: i32,
    priority: Option<i32>,
    zone_id: i32,
}
