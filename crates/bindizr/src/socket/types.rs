use std::fmt;

use bindizr_core::dns::Serial;
use bindizr_core::model::record::RecordId;
use bindizr_core::model::role_grant::RoleGrantId;
use bindizr_core::model::zone_version::VersionFilter;
use bindizr_service::types::{
    AccessLogFilter, ActivityLogFilter, ApiTokenFilter, CheckSecondariesResponse,
    CreateApiTokenRequest, CreateBulkRecordsRequest, CreateDnssecPolicyRequest,
    CreateRecordRequest, CreateRoleGrantRequest, CreateRoleRequest, CreateSecondaryRequest,
    CreateTsigKeyRequest, CreateZoneRequest, DeleteRecordsRequest, DsCheck, EnableDnssecRequest,
    Holddown, ImportDnssecKeysRequest, ImportZoneRequest, ImportZonesRequest, MessageResponse,
    NotifySerial, PageRequest, RecordFilter, Run, StartDnssecRolloverRequest, TransferLogFilter,
    TsigKeyFilter, UpdateDnssecPolicyRequest, UpdateDnssecSettingsRequest, UpdateRecordRequest,
    UpdateSecondaryRequest, UpdateZoneRequest, ZoneFilter, ZoneView,
};
use serde::{Deserialize, Serialize, Serializer};

/// A daemon command and its payload, shared by CLI serialization
/// and daemon deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", content = "data", rename_all = "snake_case")]
pub(crate) enum DaemonCommand {
    Status,
    Config,
    ReloadConfig,
    Doctor,
    Shutdown,
    Restart,
    CreateToken(CreateApiTokenRequest),
    ListTokens(ApiTokenFilter),
    DeleteToken {
        name: String,
    },
    CreateTsigKey(CreateTsigKeyRequest),
    ListTsigKeys(TsigKeyFilter),
    GetTsigKey {
        name: String,
    },
    DeleteTsigKey {
        name: String,
    },
    ListAccessLogs(AccessLogFilter),
    ListTransferLogs(TransferLogFilter),
    ListActivityLogs(ActivityLogFilter),
    CreateRole(CreateRoleRequest),
    ListRoles(PageRequest),
    GetRole {
        name: String,
    },
    DeleteRole {
        name: String,
    },
    CreateRoleGrant {
        role_name: String,
        request: CreateRoleGrantRequest,
    },
    ListRoleGrants {
        role_name: String,
        page: PageRequest,
    },
    DeleteRoleGrant {
        role_name: String,
        id: RoleGrantId,
    },
    CreateSecondary(CreateSecondaryRequest),
    ListSecondaries(PageRequest),
    GetSecondary {
        name: String,
    },
    UpdateSecondary {
        name: String,
        request: UpdateSecondaryRequest,
    },
    DeleteSecondary {
        name: String,
    },
    CheckSecondary {
        name: String,
    },
    CreateDnssecPolicy(CreateDnssecPolicyRequest),
    ListDnssecPolicies(PageRequest),
    GetDnssecPolicy {
        name: String,
    },
    UpdateDnssecPolicy {
        name: String,
        request: UpdateDnssecPolicyRequest,
    },
    DeleteDnssecPolicy {
        name: String,
    },
    CreateZone(CreateZoneRequest),
    ListZones(ZoneFilter),
    GetZone {
        name: String,
    },
    UpdateZone {
        zone_name: String,
        request: UpdateZoneRequest,
    },
    DeleteZone {
        name: String,
        run: Run,
    },
    ImportZone {
        zone_name: String,
        request: ImportZoneRequest,
    },
    ImportZones(ImportZonesRequest),
    ExportZone {
        name: String,
        view: ZoneView,
    },
    GetZoneStatus {
        name: String,
    },
    NotifyZone {
        zone_name: String,
        serial: NotifySerial,
    },
    NotifyAllZones {
        serial: NotifySerial,
    },
    ListZoneVersions {
        name: String,
        limit: Option<u32>,
        offset: Option<u64>,
        filter: VersionFilter,
    },
    GetZoneVersion {
        name: String,
        serial: Serial,
    },
    /// A missing `to_serial` compares against the current serial.
    DiffZoneVersions {
        name: String,
        from_serial: Serial,
        to_serial: Option<Serial>,
    },
    RollbackZone {
        name: String,
        serial: Serial,
        run: Run,
    },
    CreateRecord(CreateRecordRequest),
    #[serde(rename = "create_records_bulk")]
    CreateBulkRecords(CreateBulkRecordsRequest),
    ListRecords(RecordFilter),
    GetRecord {
        id: RecordId,
    },
    UpdateRecord {
        id: RecordId,
        request: UpdateRecordRequest,
    },
    /// `record_name` is the owner to update; the request's own `name` is the
    /// owner to move it to.
    UpdateRecordByName {
        zone_name: String,
        record_name: String,
        request: UpdateRecordRequest,
    },
    DeleteRecord {
        id: RecordId,
        run: Run,
    },
    #[serde(rename = "delete_records_matching")]
    DeleteMatchingRecords(DeleteRecordsRequest),
    EnableDnssec {
        zone_name: String,
        request: EnableDnssecRequest,
    },
    DisableDnssec {
        zone_name: String,
        ds_check: DsCheck,
    },
    GetDnssecStatus {
        name: String,
    },
    SignZone {
        name: String,
    },
    StartDnssecRollover {
        zone_name: String,
        request: StartDnssecRolloverRequest,
    },
    AdvanceDnssecRollover {
        zone_name: String,
        ds_check: DsCheck,
        holddown: Holddown,
    },
    WithdrawDnssec {
        name: String,
    },
    CancelDnssecWithdrawal {
        name: String,
    },
    UpdateDnssecSettings {
        zone_name: String,
        request: UpdateDnssecSettingsRequest,
    },
    CheckDnssecDs {
        name: String,
    },
    ExportDnssecKeys {
        name: String,
    },
    ImportDnssecKeys {
        zone_name: String,
        request: ImportDnssecKeysRequest,
    },
}

/// The daemon's answer: a message for a person, and the payload
/// `--output json` prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DaemonResponse<T> {
    pub(crate) message: String,
    pub(crate) data: T,
}

impl From<MessageResponse> for DaemonResponse<MessageResponse> {
    /// Use the same message for table output and the structured payload.
    fn from(response: MessageResponse) -> Self {
        Self {
            message: response.message.clone(),
            data: response,
        }
    }
}

/// Daemon status details returned by the `Status` command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DaemonStatusResponse {
    pub(crate) pid: u32,
    pub(crate) version: String,
    /// Restart detection marker: exec keeps the PID, so a new start time is
    /// the only signal that the daemon was replaced. `None` while the front
    /// ends are still starting.
    pub(crate) started_at_ms: Option<u64>,
    pub(crate) api_url: String,
    pub(crate) api_authentication: bool,
    pub(crate) dns_addr: String,
    /// The XoT listener, when a certificate is configured.
    pub(crate) dns_tls_addr: Option<String>,
    pub(crate) database_type: String,
    /// Enabled secondaries; `None` when the database did not answer.
    pub(crate) secondaries: Option<u64>,
    /// `None`, with `database_error` set, when the database did not answer;
    /// `status` prints the block and then exits non-zero.
    pub(crate) zones: Option<u64>,
    pub(crate) database_error: Option<String>,
}

/// Daemon installation checks; secondaries are compared with the catalog serial
/// as `zone status` compares them with a member zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DaemonDoctorResponse {
    pub(crate) database: DoctorCheckResponse,
    pub(crate) dns_server: DoctorCheckResponse,
    /// The XoT listener's reachability, when one is configured.
    pub(crate) dns_tls_server: Option<DoctorCheckResponse>,
    pub(crate) catalog_zone_name: String,
    /// Catalog serial served by bindizr's own DNS listener, when reachable.
    pub(crate) catalog_serial: Option<Serial>,
    /// The service's report on the enabled secondaries, flat in the payload.
    #[serde(flatten)]
    pub(crate) diagnostics: CheckSecondariesResponse,
}

/// One check's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DoctorCheckStatus {
    Ok,
    Failed,
    #[serde(rename = "skip")]
    Skipped,
}

impl DoctorCheckStatus {
    /// Return the canonical text representation.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Skipped => "skip",
        }
    }
}

impl fmt::Display for DoctorCheckStatus {
    /// Write the status as the doctor's report labels it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ok => "OK",
            Self::Failed => "FAILED",
            Self::Skipped => "SKIP",
        })
    }
}

impl Serialize for DoctorCheckStatus {
    /// Serialize through the canonical spelling used by the wire contract.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One installation check, worded as `doctor` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DoctorCheckResponse {
    pub(crate) status: DoctorCheckStatus,
    pub(crate) message: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that socket command strings stay stable when Rust variants are renamed.
    #[test]
    fn command_names_preserve_the_wire_contract() {
        for (command, expected) in [
            (
                DaemonCommand::CreateBulkRecords(CreateBulkRecordsRequest {
                    zone_name: "example.com".to_string(),
                    records: Vec::new(),
                    dry_run: true,
                }),
                "create_records_bulk",
            ),
            (
                DaemonCommand::DeleteMatchingRecords(DeleteRecordsRequest {
                    zone_name: "example.com".to_string(),
                    name: "www".to_string(),
                    record_type: None,
                    value: None,
                    priority: None,
                    dry_run: true,
                }),
                "delete_records_matching",
            ),
            (
                DaemonCommand::AdvanceDnssecRollover {
                    zone_name: "example.com".to_string(),
                    ds_check: DsCheck::Probe,
                    holddown: Holddown::Wait,
                },
                "advance_dnssec_rollover",
            ),
        ] {
            let value = serde_json::to_value(&command).unwrap();
            assert_eq!(value["command"], expected);
            assert_eq!(
                serde_json::from_value::<DaemonCommand>(value).unwrap(),
                command
            );
        }
    }

    /// Verify that `DoctorCheckStatus` has one spelling across `as_str` and serde.
    #[test]
    fn doctor_check_status_spells_itself_once() {
        for value in [
            DoctorCheckStatus::Ok,
            DoctorCheckStatus::Failed,
            DoctorCheckStatus::Skipped,
        ] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<DoctorCheckStatus>(json!(value.as_str())).unwrap(),
                value
            );
        }
    }
}
