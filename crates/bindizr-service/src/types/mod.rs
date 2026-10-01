//! Request and response payloads, grouped by entity and re-exported as `types::X`.
//! HTTP and the daemon socket share this contract; CLI responses also need `Deserialize`.

mod common;
mod dnssec;
mod dnssec_policy;
mod external_dns;
mod grant;
mod import;
mod pagination;
mod record;
mod secondary;
mod token;
mod token_grant;
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
pub use grant::CreateGrantRequest;
pub use import::{ImportMode, ImportSummary, ImportZoneRequest, ImportZoneResponse};
pub use pagination::{DEFAULT_PAGE_LIMIT, PageRequest, PaginatedResponse, Pagination};
pub(crate) use record::build_display_value;
pub use record::{
    BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, DeleteRecordsRequest,
    DeleteRecordsResponse, GetRecordResponse, GetRecordsFilter, RecordItem, RecordResponse,
    RecordValueRequest, RecordWriteResponse, UpdateRecordRequest,
};
pub use secondary::{
    CreateSecondaryRequest, GetSecondaryResponse, GetSecondaryTransfersFilter, NotifyCheckResponse,
    SecondaryCheckResponse, SecondaryResponse, SecondaryTransferSummary,
    SecondaryTransfersResponse, TransferResponse, TransferSummary, UpdateSecondaryRequest,
};
pub use token::{CreateTokenRequest, CreatedTokenResponse, GetTokenResponse, TokenResponse};
pub use token_grant::{GetTokenGrantResponse, TokenGrantResponse};
pub use tsig::{
    CreateTsigKeyRequest, GetTsigGrantResponse, GetTsigKeyResponse, TsigGrantResponse,
    TsigKeyResponse,
};
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
