use crate::config::BindizrConfig;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonCommandKind {
    Status,
    TokenCreate,
    TokenList,
    TokenDelete,
    // Zone commands
    GetZone,
    ListZones,
    CreateZone,
    DeleteZone,
    // Record commands
    GetRecord,
    ListRecords,
    CreateRecord,
    DeleteRecord,
    // Notify commands
    NotifyZone,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DaemonCommand {
    pub command: DaemonCommandKind,
    pub data: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DaemonResponse {
    pub message: String,
    pub data: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DaemonStatusResponse {
    pub pid: Option<u32>,
    pub version: String,
    pub config: BindizrConfig,
}
