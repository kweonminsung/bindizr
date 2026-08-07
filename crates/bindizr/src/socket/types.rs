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
    TsigKeyCreate,
    TsigKeyList,
    TsigKeyGet,
    TsigKeyDelete,
    ZoneTsigPolicyAdd,
    ZoneTsigPolicyList,
    ZoneTsigPolicyRemove,
    ZoneTokenPolicyAdd,
    ZoneTokenPolicyList,
    ZoneTokenPolicyRemove,
    GetZone,
    ListZones,
    CreateZone,
    UpdateZone,
    DeleteZone,
    GetRecord,
    ListRecords,
    CreateRecord,
    UpdateRecord,
    BulkCreateRecords,
    DeleteRecord,
    NotifyZone,
    ImportZoneFile,
    ExportZoneFile,
    ListZoneSnapshots,
    GetZoneSnapshot,
    DiffZoneSnapshots,
    RollbackZone,
    ZoneStatus,
    Doctor,
    Shutdown,
    Restart,
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
    /// Restart detection marker: exec keeps the PID, so a new start time is
    /// the only signal that the daemon was replaced.
    pub started_at_ms: u64,
    pub config: BindizrConfig,
}

/// Daemon-side installation checks returned by the `Doctor` command.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonDoctorResponse {
    pub database: DoctorCheckResult,
    pub dns_server: DoctorCheckResult,
    /// Catalog serial served by bindizr's own DNS listener, when reachable.
    pub catalog_serial: Option<u32>,
    pub secondaries: Vec<DoctorProbeResult>,
    pub notifies: Vec<DoctorProbeResult>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DoctorCheckResult {
    pub ok: bool,
    pub detail: String,
}

/// One secondary's SOA probe or NOTIFY outcome; `error` is set on failure.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DoctorProbeResult {
    pub address: String,
    pub serial: Option<u32>,
    pub error: Option<String>,
}
