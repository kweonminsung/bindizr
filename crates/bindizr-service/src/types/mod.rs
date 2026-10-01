//! Request and response payloads, grouped by entity and re-exported as `types::X`.
//! HTTP and the daemon socket share this contract; CLI responses also need `Deserialize`.

mod common;
mod dnssec;
mod dnssec_policy;
mod external_dns;
mod import;
mod pagination;
mod record;
mod role;
mod secondary;
mod token;
mod tsig;
mod version;
mod zone;

pub use common::{ErrorResponse, HealthResponse, HealthStatus, MessageResponse, Run};
pub use dnssec::{
    DnssecDelegationInfo, DnssecDelegationKeyInfo, DnssecDsInfo, DnssecKeyInfo, DnssecKeyMaterial,
    DnssecStatusResponse, DsCheck, DsState, EnableDnssecRequest, ExportDnssecKeysResponse,
    Holddown, ImportDnssecKeyPair, ImportDnssecKeyRequest, RolloverDnssecRequest,
    UpdateDnssecSettingsRequest,
};
pub use dnssec_policy::{
    CreateDnssecPolicyRequest, DnssecPolicyResponse, GetDnssecPolicyResponse,
    UpdateDnssecPolicyRequest,
};
pub use external_dns::{
    ExternalDnsAdjustRequest, ExternalDnsAdjustResponse, ExternalDnsChangesRequest,
    ExternalDnsChangesResponse, ExternalDnsDomainsResponse, ExternalDnsRecord,
    ExternalDnsRecordUpdate, ExternalDnsRecordsResponse,
};
pub use import::{
    ImportMode, ImportSummary, ImportZoneRequest, ImportZoneResponse, ParseImportModeError,
};
pub use pagination::{DEFAULT_PAGE_LIMIT, PageRequest, PaginatedResponse, Pagination};
pub(crate) use record::build_display_value;
pub use record::{
    BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, DeleteRecordsRequest,
    DeleteRecordsResponse, GetRecordResponse, GetRecordsFilter, RecordItem, RecordResponse,
    RecordTypeResponse, RecordValueRequest, RecordWriteResponse, UpdateRecordRequest,
};
pub use role::{
    CreateRoleGrantRequest, CreateRoleRequest, GetRoleGrantResponse, GetRoleResponse,
    RoleGrantResponse, RoleResponse,
};
pub use secondary::{
    CreateSecondaryRequest, GetSecondaryResponse, GetSecondaryTransfersFilter, NotifyCheckResponse,
    SecondaryCheckResponse, SecondaryResponse, SecondaryTransferSummary,
    SecondaryTransfersResponse, TransferResponse, TransferSummary, UpdateSecondaryRequest,
};
pub use token::{
    CreateTokenRequest, CreatedTokenResponse, GetTokenResponse, TokenFilter, TokenResponse,
};
pub use tsig::{CreateTsigKeyRequest, GetTsigKeyResponse, TsigKeyFilter, TsigKeyResponse};
pub use version::{
    RecordChange, RecordDiff, RecordDiffEntry, RecordDiffSummary, RecordDiffValue, RollbackSummary,
    RollbackZoneResponse, VersionDetailResponse, VersionDiffResponse, VersionRecordResponse,
    ZoneVersionResponse,
};
pub use zone::{
    CreateZoneRequest, DeleteZoneResponse, ExportZoneFileResponse, GetZoneResponse, GetZonesFilter,
    NotifySerial, SecondaryStatus, SecondaryStatusResponse, UpdateZoneRequest, ZoneResponse,
    ZoneStatusResponse, ZoneView, ZoneWriteResponse, build_notify_message,
};
