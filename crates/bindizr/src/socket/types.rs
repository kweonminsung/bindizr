use bindizr_core::{
    dns::Serial,
    model::{record::RecordId, role_grant::RoleGrantId, zone_version::VersionFilter},
};
use bindizr_service::types::{
    CreateBulkRecordsRequest, CreateDnssecPolicyRequest, CreateRecordRequest,
    CreateRoleGrantRequest, CreateRoleRequest, CreateSecondaryRequest, CreateTokenRequest,
    CreateTsigKeyRequest, CreateZoneRequest, DeleteRecordsRequest, DsCheck, EnableDnssecRequest,
    GetRecordsFilter, GetSecondaryTransfersFilter, GetZonesFilter, Holddown,
    ImportDnssecKeyRequest, ImportZoneRequest, NotifyCheckResponse, NotifySerial, PageRequest,
    RolloverDnssecRequest, Run, SecondaryStatusResponse, SecondaryTransferSummary, TokenFilter,
    TsigKeyFilter, UpdateDnssecPolicyRequest, UpdateDnssecSettingsRequest, UpdateRecordRequest,
    UpdateSecondaryRequest, UpdateZoneRequest, ZoneView,
};
use serde::{Deserialize, Serialize};

/// A daemon command and its payload, shared by CLI serialization
/// and daemon deserialization.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "command", content = "data", rename_all = "snake_case")]
pub(crate) enum DaemonCommand {
    Status,
    Config,
    ReloadConfig,
    Doctor,
    Shutdown,
    Restart,
    CreateToken(CreateTokenRequest),
    ListTokens(TokenFilter),
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
    ListSecondaryTransfers {
        name: String,
        filter: GetSecondaryTransfersFilter,
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
    ListZones(GetZonesFilter),
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
    CreateRecordsBulk(CreateBulkRecordsRequest),
    ListRecords(GetRecordsFilter),
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
    DeleteRecordsMatching(DeleteRecordsRequest),
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
        request: RolloverDnssecRequest,
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
        request: ImportDnssecKeyRequest,
    },
}

/// The daemon's answer: a message for a person, and the payload
/// `--output json` prints.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct DaemonResponse<T> {
    pub(crate) message: String,
    pub(crate) data: T,
}

/// Daemon status details returned by the `Status` command.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct DaemonDoctorResponse {
    pub(crate) database: DoctorCheck,
    pub(crate) dns_server: DoctorCheck,
    pub(crate) catalog_zone_name: String,
    /// Catalog serial served by bindizr's own DNS listener, when reachable.
    pub(crate) catalog_serial: Option<Serial>,
    pub(crate) secondaries: Vec<SecondaryStatusResponse>,
    pub(crate) notifies: Vec<NotifyCheckResponse>,
    /// How Bindizr served each enabled secondary.
    pub(crate) transfers: Vec<SecondaryTransferSummary>,
}

/// One check's outcome.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DoctorCheckStatus {
    Ok,
    Failed,
    #[serde(rename = "skip")]
    Skipped,
}

impl std::fmt::Display for DoctorCheckStatus {
    /// Write the status as the doctor's report labels it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DoctorCheckStatus::Ok => "OK",
            DoctorCheckStatus::Failed => "FAILED",
            DoctorCheckStatus::Skipped => "SKIP",
        })
    }
}

/// One installation check, worded as `doctor` reports it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoctorCheck {
    pub(crate) status: DoctorCheckStatus,
    pub(crate) message: String,
}

impl DoctorCheckStatus {
    /// Return the canonical wire spelling.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Skipped => "skip",
        }
    }
}

impl serde::Serialize for DoctorCheckStatus {
    /// Serialize through the canonical spelling used by the wire contract.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the canonical spelling and round-trip of every DoctorCheckStatus variant.
    #[test]
    fn doctor_check_status_spells_itself_once() {
        for (value, expected) in [
            (DoctorCheckStatus::Ok, "ok"),
            (DoctorCheckStatus::Failed, "failed"),
            (DoctorCheckStatus::Skipped, "skip"),
        ] {
            assert_eq!(value.as_str(), expected);
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(expected)
            );
            assert_eq!(
                serde_json::from_value::<DoctorCheckStatus>(serde_json::json!(expected)).unwrap(),
                value
            );
        }
    }
}
