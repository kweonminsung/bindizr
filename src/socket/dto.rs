use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonCommandKind {
    Status,
    TokenCreate,
    TokenList,
    TokenDelete,
    DnsWriteConfig,
    DnsReload,
    DnsStatus,
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
    pub pid: Option<i32>,
    pub version: String,
    pub config_map: serde_json::Value,
}
