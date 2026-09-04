use bindizr_core::config::BindizrConfig;
use bindizr_service::types::{
    CreateBulkRecordsRequest, CreateZoneTokenPolicyRequest, CreateZoneTsigPolicyRequest,
    EnableDnssecRequest, ImportDnssecKeyRequest, ImportZoneFileRequest,
    ImportZoneFromServerRequest, RollbackZoneRequest, RolloverDnssecRequest,
    SetZoneDnssecPolicyRequest, UpdateDnssecPolicyRequest, UpdateRecordPatch, UpdateZonePatch,
};
use serde::{Deserialize, Serialize};

/// Command kinds accepted by the daemon over the Unix socket.
#[derive(Serialize, Deserialize, Debug)]
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
    DnssecPolicyCreate,
    DnssecPolicyList,
    DnssecPolicyGet,
    DnssecPolicyUpdate,
    DnssecPolicyDelete,
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
    ImportZoneFromServer,
    ExportZoneFile,
    ListZoneVersions,
    GetZoneVersion,
    DiffZoneVersions,
    RollbackZone,
    ZoneStatus,
    ZoneDnssecEnable,
    ZoneDnssecDisable,
    ZoneDnssecStatus,
    ZoneDnssecSign,
    ZoneDnssecRolloverStart,
    ZoneDnssecRolloverDsSeen,
    ZoneDnssecWithdraw,
    ZoneDnssecWithdrawCancel,
    ZoneDnssecSetPolicy,
    ZoneDnssecKeysExport,
    ZoneDnssecKeysImport,
    Doctor,
    Shutdown,
    Restart,
}

/// A command and its payload sent to the daemon.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonCommand {
    pub(crate) command: DaemonCommandKind,
    pub(crate) data: serde_json::Value,
}

/// A message and payload returned by the daemon.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonResponse {
    pub(crate) message: String,
    pub(crate) data: serde_json::Value,
}

// The CLI serializes one of these and the daemon deserializes the same type, so
// a renamed field breaks at compile time. A payload that is exactly a service
// request type is sent as that type.

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ZoneNameParams {
    pub(crate) name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RecordIdParams {
    pub(crate) id: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TsigKeyNameParams {
    pub(crate) name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DnssecPolicyNameParams {
    pub(crate) name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UpdateDnssecPolicyParams {
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) request: UpdateDnssecPolicyRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TokenNameParams {
    pub(crate) name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ZonePolicyListParams {
    pub(crate) zone_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RemoveZonePolicyParams {
    pub(crate) zone_name: String,
    pub(crate) id: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AddZoneTsigPolicyParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: CreateZoneTsigPolicyRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AddZoneTokenPolicyParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: CreateZoneTokenPolicyRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExportZoneFileParams {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) signed: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ImportZoneFileParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: ImportZoneFileRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ImportZoneFromServerParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: ImportZoneFromServerRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BulkCreateRecordsParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: CreateBulkRecordsRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UpdateZoneParams {
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) patch: UpdateZonePatch,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UpdateRecordParams {
    pub(crate) id: i32,
    #[serde(flatten)]
    pub(crate) patch: UpdateRecordPatch,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RollbackZoneParams {
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) request: RollbackZoneRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListZoneVersionsParams {
    pub(crate) name: String,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u64>,
    #[serde(default)]
    pub(crate) all: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ZoneVersionParams {
    pub(crate) name: String,
    pub(crate) serial: i32,
}

/// Payload for diffing two of a zone's serials; a missing `to_serial` compares
/// against the current serial.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DiffZoneVersionsParams {
    pub(crate) name: String,
    pub(crate) from_serial: i32,
    pub(crate) to_serial: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EnableZoneDnssecParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: EnableDnssecRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RolloverZoneDnssecParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: RolloverDnssecRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ImportZoneDnssecKeyParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: ImportDnssecKeyRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SetZoneDnssecPolicyParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: SetZoneDnssecPolicyRequest,
}

/// Daemon status details returned by the `Status` command.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonStatusResponse {
    pub(crate) pid: Option<u32>,
    pub(crate) version: String,
    /// Restart detection marker: exec keeps the PID, so a new start time is
    /// the only signal that the daemon was replaced.
    pub(crate) started_at_ms: u64,
    pub(crate) config: BindizrConfig,
}

/// Daemon-side installation checks returned by the `Doctor` command.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonDoctorResponse {
    pub(crate) database: DoctorCheckResult,
    pub(crate) dns_server: DoctorCheckResult,
    /// Catalog serial served by bindizr's own DNS listener, when reachable.
    pub(crate) catalog_serial: Option<u32>,
    pub(crate) secondaries: Vec<DoctorProbeResult>,
    pub(crate) notifies: Vec<DoctorProbeResult>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DoctorCheckResult {
    pub(crate) ok: bool,
    pub(crate) detail: String,
}

/// One secondary's SOA probe or NOTIFY outcome; `error` is set on failure.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DoctorProbeResult {
    pub(crate) address: String,
    pub(crate) serial: Option<u32>,
    pub(crate) error: Option<String>,
}
