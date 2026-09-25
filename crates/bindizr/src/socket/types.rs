use bindizr_service::types::{
    CreateGrantRequest, EnableDnssecRequest, ImportDnssecKeyRequest, ImportZoneRequest,
    NotifyCheckResponse, PageFilter, RolloverDnssecRequest, SecondaryStatusResponse,
    UpdateDnssecPolicyRequest, UpdateDnssecSettingsRequest, UpdateRecordRequest,
    UpdateSecondaryRequest, UpdateZoneRequest,
};
use serde::{Deserialize, Serialize};

/// Command kinds accepted by the daemon over the Unix socket.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DaemonCommandKind {
    Status,
    Config,
    ReloadConfig,
    CreateToken,
    ListTokens,
    DeleteToken,
    CreateSecondary,
    ListSecondaries,
    GetSecondary,
    UpdateSecondary,
    DeleteSecondary,
    CheckSecondary,
    CreateTsigKey,
    ListTsigKeys,
    GetTsigKey,
    DeleteTsigKey,
    CreateDnssecPolicy,
    ListDnssecPolicies,
    GetDnssecPolicy,
    UpdateDnssecPolicy,
    DeleteDnssecPolicy,
    CreateTsigGrant,
    ListTsigGrants,
    ListZoneTsigGrants,
    DeleteTsigGrant,
    DeleteTsigGrantsByKeyAndZone,
    CreateTokenGrant,
    ListTokenGrants,
    ListZoneTokenGrants,
    DeleteTokenGrant,
    DeleteTokenGrantsByTokenAndZone,
    GetZone,
    ListZones,
    CreateZone,
    UpdateZone,
    DeleteZone,
    GetRecord,
    ListRecords,
    CreateRecord,
    UpdateRecord,
    UpdateRecordByName,
    CreateRecordsBulk,
    DeleteRecord,
    DeleteRecordsMatching,
    NotifyAllZones,
    NotifyZone,
    ImportZone,
    ExportZone,
    ListZoneVersions,
    GetZoneVersion,
    DiffZoneVersions,
    RollbackZone,
    GetZoneStatus,
    EnableDnssec,
    DisableDnssec,
    GetDnssecStatus,
    SignZone,
    StartDnssecRollover,
    DsSeenDnssecRollover,
    WithdrawDnssec,
    CancelDnssecWithdrawal,
    UpdateDnssecSettings,
    CheckDnssecDs,
    ExportDnssecKeys,
    ImportDnssecKeys,
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

/// Parameters for deleting a zone by name.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteZoneParams {
    pub(crate) name: String,
    /// Report what the delete would take without removing it.
    #[serde(default)]
    pub(crate) dry_run: bool,
}

/// Parameters for deleting one record by id.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteRecordParams {
    pub(crate) id: i32,
    /// Report what would go without removing it, as the filtered delete does.
    #[serde(default)]
    pub(crate) dry_run: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateSecondaryParams {
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) request: UpdateSecondaryRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateDnssecPolicyParams {
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) request: UpdateDnssecPolicyRequest,
}

/// Payload for listing the grants of one named subject: a TSIG key, an API
/// token, or a zone, all of which are keyed the same way.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListGrantsParams {
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) page: PageFilter,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateTsigGrantParams {
    pub(crate) key_name: String,
    #[serde(flatten)]
    pub(crate) request: CreateGrantRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateTokenGrantParams {
    pub(crate) token_name: String,
    #[serde(flatten)]
    pub(crate) request: CreateGrantRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteTsigGrantsByKeyAndZoneParams {
    pub(crate) key_name: String,
    pub(crate) zone_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteTokenGrantsByTokenAndZoneParams {
    pub(crate) token_name: String,
    pub(crate) zone_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportZoneFileParams {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) signed: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportZoneParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: ImportZoneRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateZoneParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: UpdateZoneRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateRecordParams {
    pub(crate) id: i32,
    #[serde(flatten)]
    pub(crate) request: UpdateRecordRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateRecordByNameParams {
    pub(crate) zone_name: String,
    /// The owner to update, kept apart from the request's own `name` — the
    /// owner to move it to. Flattened into one object they are the same key,
    /// and the move would pick the record it means to create.
    pub(crate) record_name: String,
    #[serde(flatten)]
    pub(crate) request: UpdateRecordRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotifyAllZonesParams {
    #[serde(default)]
    pub(crate) bump_serial: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotifyZoneParams {
    pub(crate) zone_name: String,
    #[serde(default)]
    pub(crate) bump_serial: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct RollbackZoneParams {
    pub(crate) name: String,
    pub(crate) serial: u32,
    #[serde(default)]
    pub(crate) dry_run: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListZoneVersionsParams {
    pub(crate) name: String,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u64>,
    #[serde(default)]
    pub(crate) include_signer_serials: bool,
}

/// One of a zone's versions, by name and serial.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ZoneVersionParams {
    pub(crate) name: String,
    pub(crate) serial: u32,
}

/// Payload for diffing two of a zone's serials; a missing `to_serial` compares
/// against the current serial.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiffZoneVersionsParams {
    pub(crate) name: String,
    pub(crate) from_serial: u32,
    pub(crate) to_serial: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnableZoneDnssecParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: EnableDnssecRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct RolloverZoneDnssecParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: RolloverDnssecRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportZoneDnssecKeysParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: ImportDnssecKeyRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateZoneDnssecSettingsParams {
    pub(crate) zone_name: String,
    #[serde(flatten)]
    pub(crate) request: UpdateDnssecSettingsRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct DisableZoneDnssecParams {
    pub(crate) zone_name: String,
    pub(crate) skip_ds_check: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct DsSeenZoneDnssecParams {
    pub(crate) zone_name: String,
    pub(crate) skip_ds_check: bool,
    pub(crate) skip_holddown: bool,
}

/// Daemon status details returned by the `Status` command.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonStatusResponse {
    pub(crate) pid: Option<u32>,
    pub(crate) version: String,
    /// Restart detection marker: exec keeps the PID, so a new start time is
    /// the only signal that the daemon was replaced.
    pub(crate) started_at_ms: u64,
    pub(crate) api_url: String,
    pub(crate) api_authentication: bool,
    pub(crate) dns_addr: String,
    pub(crate) database_type: String,
    /// Enabled secondaries; `None` when the database did not answer.
    pub(crate) secondaries: Option<usize>,
    /// `None`, with `database_error` set, when the database did not answer;
    /// `status` prints the block and then exits non-zero.
    pub(crate) zones: Option<u64>,
    pub(crate) database_error: Option<String>,
}

/// Daemon-side installation checks returned by the `Doctor` command. The
/// secondaries are classified against the catalog zone's serial, the way
/// `zone status` classifies them against a member zone's.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DaemonDoctorResponse {
    pub(crate) database: DoctorCheckResult,
    pub(crate) dns_server: DoctorCheckResult,
    pub(crate) catalog_zone_name: String,
    /// Catalog serial served by bindizr's own DNS listener, when reachable.
    pub(crate) catalog_serial: Option<u32>,
    pub(crate) secondaries: Vec<SecondaryStatusResponse>,
    pub(crate) notifies: Vec<NotifyCheckResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DoctorCheckResult {
    pub(crate) ok: bool,
    pub(crate) detail: String,
}
