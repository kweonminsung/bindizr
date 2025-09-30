use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DaemonCommand {
    pub command: String,
    pub data: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DaemonResponse {
    pub message: String,
    pub data: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DaemonStatusResponse {
    pub pid: Option<i32>,
    pub version: String,
    pub config_map: serde_json::Value,
}
