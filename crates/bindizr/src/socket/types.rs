use bindizr_core::config::BindizrConfig;
use serde::{Deserialize, Serialize};

use crate::api::types::{
    CreateBulkRecordsRequest, CreateZoneTokenPolicyRequest, CreateZoneTsigPolicyRequest,
    ImportZoneFileRequest, RollbackZoneRequest, UpdateRecordPatch, UpdateZonePatch,
};

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

// Command payloads. The CLI serializes one and the daemon deserializes the same
// type, so a renamed field breaks at compile time. A payload that is exactly a
// service request type is sent as that type.

/// Payload addressing a zone by name.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ZoneNameParams {
    pub name: String,
}

/// Payload addressing a record by id.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RecordIdParams {
    pub id: i32,
}

/// Payload addressing a TSIG key by name.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TsigKeyNameParams {
    pub name: String,
}

/// Payload addressing an API token by name.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TokenNameParams {
    pub name: String,
}

/// Payload for creating an API token.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateTokenParams {
    pub name: String,
    pub description: Option<String>,
    pub expires_in_days: Option<i64>,
    #[serde(default)]
    pub global: bool,
}

/// Payload addressing a zone's policies.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ZonePolicyListParams {
    pub zone_name: String,
}

/// Payload addressing one policy row within a zone.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RemoveZonePolicyParams {
    pub zone_name: String,
    pub id: i32,
}

/// Payload for granting a TSIG key a policy on a zone.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AddZoneTsigPolicyParams {
    pub zone_name: String,
    #[serde(flatten)]
    pub request: CreateZoneTsigPolicyRequest,
}

/// Payload for granting a token a policy on a zone.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AddZoneTokenPolicyParams {
    pub zone_name: String,
    #[serde(flatten)]
    pub request: CreateZoneTokenPolicyRequest,
}

/// Payload for importing zone-file text into a zone.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ImportZoneFileParams {
    pub zone_name: String,
    #[serde(flatten)]
    pub request: ImportZoneFileRequest,
}

/// Payload for inserting records into a zone in one transaction.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BulkCreateRecordsParams {
    pub zone_name: String,
    #[serde(flatten)]
    pub request: CreateBulkRecordsRequest,
}

/// Payload for patching a zone.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UpdateZoneParams {
    pub name: String,
    #[serde(flatten)]
    pub patch: UpdateZonePatch,
}

/// Payload for patching a record.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UpdateRecordParams {
    pub id: i32,
    #[serde(flatten)]
    pub patch: UpdateRecordPatch,
}

/// Payload for rolling a zone back to a snapshot serial.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RollbackZoneParams {
    pub name: String,
    #[serde(flatten)]
    pub request: RollbackZoneRequest,
}

/// Payload for listing a zone's snapshots.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListZoneSnapshotsParams {
    pub name: String,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// Payload addressing one of a zone's snapshots.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ZoneSnapshotParams {
    pub name: String,
    pub serial: i32,
}

/// Payload for diffing two of a zone's serials; a missing `to_serial` compares
/// against the current serial.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DiffZoneSnapshotsParams {
    pub name: String,
    pub from_serial: i32,
    pub to_serial: Option<i32>,
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
