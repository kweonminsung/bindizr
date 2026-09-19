//! Service-layer request and response payloads, grouped by the entity they
//! belong to. Re-exported flat so callers keep naming them `types::X`.
//!
//! These are the wire contract of every front end, not just HTTP: the daemon
//! socket carries the same shapes, so a response type the CLI reads back
//! derives `Deserialize` too.

mod common;
mod dnssec;
mod dnssec_policy;
mod external_dns;
mod import;
mod pagination;
mod record;
mod token;
mod token_grant;
mod tsig;
mod version;
mod zone;

pub use common::{ErrorResponse, HealthResponse, MessageResponse};
pub use dnssec::{
    DnssecDelegationInfo, DnssecDelegationKeyInfo, DnssecDsInfo, DnssecKeyInfo, DnssecKeyMaterial,
    DnssecStatusResponse, EnableDnssecRequest, ExportDnssecKeysResponse, GetDnssecStatusResponse,
    ImportDnssecKeyPair, ImportDnssecKeyRequest, RolloverDnssecRequest,
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
pub use import::{ImportMode, ImportSummary, ImportZoneRequest, ImportZoneResponse};
pub use pagination::{DEFAULT_PAGE_LIMIT, PageFilter, PaginatedResponse, Pagination};
pub(crate) use pagination::{normalize_page_limit, parse_setting};
pub(crate) use record::build_display_value;
pub use record::{
    BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, DeleteRecordsFilter,
    DeleteRecordsResponse, GetRecordResponse, GetRecordsFilter, RecordItem, RecordResponse,
    RecordValueRequest, RecordWriteResponse, UpdateRecordRequest,
};
pub use token::{CreateTokenRequest, CreatedTokenResponse, GetTokenResponse, TokenResponse};
pub use token_grant::{CreateTokenGrantRequest, GetTokenGrantResponse, TokenGrantResponse};
pub use tsig::{
    CreateTsigGrantRequest, CreateTsigKeyRequest, GetTsigGrantResponse, GetTsigKeyResponse,
    TsigGrantResponse, TsigKeyResponse,
};
pub use version::{
    RecordDiff, RecordDiffEntry, RecordDiffSummary, RecordDiffValue, RollbackSummary,
    RollbackZoneResponse, VersionDetailResponse, VersionDiffResponse, VersionRecordResponse,
    ZoneVersionResponse,
};
pub use zone::{
    CreateZoneRequest, DeleteZoneResponse, ExportZoneFileResponse, GetZoneResponse, GetZonesFilter,
    SecondaryStatusResponse, UpdateZoneRequest, ZoneResponse, ZoneStatusResponse,
    ZoneWriteResponse, build_notify_message,
};
