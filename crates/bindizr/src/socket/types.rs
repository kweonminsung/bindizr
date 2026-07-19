use bindizr_core::config::BindizrConfig;
use serde::{Deserialize, Serialize};

/// Command kinds accepted by the daemon over the Unix socket.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DaemonCommandKind {
    Status,
    TokenCreate,
    TokenList,
    TokenDelete,
    GetZone,
    ListZones,
    CreateZone,
    DeleteZone,
    GetRecord,
    ListRecords,
    CreateRecord,
    DeleteRecord,
    NotifyZone,
}

/// A command and its payload sent to the daemon.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonCommand {
    pub command: DaemonCommandKind,
    pub data: serde_json::Value,
}

/// A message and payload returned by the daemon.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonResponse {
    pub message: String,
    pub data: serde_json::Value,
}

/// Daemon status details returned by the `Status` command.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonStatusResponse {
    pub pid: Option<u32>,
    pub version: String,
    pub config: BindizrConfig,
}
