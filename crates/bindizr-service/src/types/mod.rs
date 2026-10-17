//! Request and response payloads, grouped by entity and re-exported as `types::X`.
//! HTTP and the daemon socket share this contract; CLI responses also need `Deserialize`.

mod audit;
mod common;
mod dnssec;
mod dnssec_policy;
mod external_dns;
mod import;
mod pagination;
mod permission;
mod record;
mod role;
mod secondary;
mod token;
mod tsig;
mod version;
mod zone;

pub use audit::{AuditLogFilter, AuditLogResponse};
pub use common::{ErrorResponse, HealthResponse, HealthStatus, MessageResponse, Run};
pub use dnssec::{
    DnssecDelegationKeyResponse, DnssecDelegationResponse, DnssecDsResponse,
    DnssecKeyMaterialResponse, DnssecKeyResponse, DnssecStatusResponse, DsCheck, DsState,
    EnableDnssecRequest, ExportDnssecKeysResponse, Holddown, ImportDnssecKeyPair,
    ImportDnssecKeysRequest, StartDnssecRolloverRequest, UpdateDnssecSettingsRequest,
};
pub use dnssec_policy::{
    CreateDnssecPolicyRequest, DnssecPolicyResponse, SingleDnssecPolicyResponse,
    UpdateDnssecPolicyRequest,
};
pub use external_dns::{
    AdjustExternalDnsRecordsRequest, AdjustExternalDnsRecordsResponse,
    ApplyExternalDnsChangesRequest, ApplyExternalDnsChangesResponse, ExternalDnsRecord,
    ExternalDnsRecordUpdate, ListExternalDnsDomainsResponse, ListExternalDnsRecordsResponse,
};
pub use import::{
    ImportMode, ImportResult, ImportZoneRequest, ImportZoneResponse, ImportZoneSummaryResponse,
    ImportZonesItemResponse, ImportZonesRequest, ImportZonesResponse, ImportZonesSummaryResponse,
    ParseImportModeError,
};
pub use pagination::{DEFAULT_PAGE_LIMIT, PageRequest, PaginatedResponse, PaginationResponse};
pub use permission::{PermissionsResponse, PermittedActionsResponse, ZonePermissionsResponse};
pub(crate) use record::build_display_value;
pub use record::{
    BulkRecordItem, CreateBulkRecordsRequest, CreateBulkRecordsResponse, CreateRecordRequest,
    DeleteRecordsRequest, DeleteRecordsResponse, RecordFilter, RecordResponse, RecordValue,
    ServedRecordType, SingleRecordResponse, UpdateRecordRequest, WriteRecordResponse,
};
pub use role::{
    CreateRoleGrantRequest, CreateRoleRequest, RoleGrantResponse, RoleResponse,
    SingleRoleGrantResponse, SingleRoleResponse,
};
pub use secondary::{
    CheckNotifyResponse, CheckSecondaryResponse, CreateSecondaryRequest, SecondaryResponse,
    SecondaryTransferFilter, SecondaryTransferSummaryResponse, SecondaryTransfersResponse,
    SingleSecondaryResponse, TransferResponse, TransferSummaryResponse, UpdateSecondaryRequest,
};
pub use token::{
    CreateTokenRequest, CreateTokenResponse, SingleTokenResponse, TokenFilter, TokenResponse,
};
pub use tsig::{CreateTsigKeyRequest, SingleTsigKeyResponse, TsigKeyFilter, TsigKeyResponse};
pub use version::{
    DiffZoneVersionsResponse, GetZoneVersionResponse, RecordChange, RecordDiffEntryResponse,
    RecordDiffResponse, RecordDiffSummaryResponse, RecordDiffValueResponse, RollbackZoneResponse,
    RollbackZoneSummaryResponse, VersionRecordResponse, ZoneVersionResponse,
};
pub use zone::{
    CreateZoneRequest, DeleteZoneResponse, ExportZoneFileResponse, NotifySerial, SecondaryStatus,
    SecondaryStatusResponse, SingleZoneResponse, UpdateZoneRequest, WriteZoneResponse, ZoneFilter,
    ZoneResponse, ZoneStatusResponse, ZoneView, build_notify_message,
};
