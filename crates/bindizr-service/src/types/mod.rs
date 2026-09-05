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
    DnssecDsInfo, DnssecDsListResponse, DnssecKeyInfo, DnssecKeyMaterial, DnssecStatusResponse,
    EnableDnssecRequest, ExportDnssecKeysResponse, GetDnssecStatusResponse, ImportDnssecKeyPair,
    ImportDnssecKeyRequest, RolloverDnssecRequest, SetZoneDnssecPolicyRequest,
};
pub use dnssec_policy::{
    CreateDnssecPolicyRequest, DnssecPolicyListResponse, DnssecPolicyResponse,
    GetDnssecPolicyResponse, UpdateDnssecPolicyRequest,
};
pub use external_dns::{
    ExternalDnsAdjustRequest, ExternalDnsAdjustResponse, ExternalDnsChangesRequest,
    ExternalDnsChangesResponse, ExternalDnsRecordItem, ExternalDnsRecordsResponse,
    ExternalDnsRrset, ExternalDnsRrsetUpdate, ExternalDnsZonesResponse,
};
pub use import::{
    ImportMode, ImportSummary, ImportZoneFileRequest, ImportZoneFileResponse,
    ImportZoneFromServerRequest,
};
pub use pagination::{PaginatedResponse, Pagination};
pub(crate) use record::display_record_value_request;
pub use record::{
    BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, GetRecordResponse,
    GetRecordsFilter, RecordItem, RecordResponse, RecordValueRequest, UpdateRecordPatch,
};
pub use token::{CreateTokenRequest, CreatedTokenResponse, GetTokenResponse, TokenListResponse};
pub use token_grant::{
    CreateTokenGrantRequest, GetTokenGrantResponse, TokenGrantListResponse, TokenGrantResponse,
};
pub use tsig::{
    CreateTsigGrantRequest, CreateTsigKeyRequest, GetTsigGrantResponse, GetTsigKeyResponse,
    TsigGrantListResponse, TsigGrantResponse, TsigKeyListResponse, TsigKeyResponse,
};
pub use version::{
    RecordDiff, RecordDiffEntry, RecordDiffSummary, RecordDiffValue, RollbackSummary,
    RollbackZoneRequest, RollbackZoneResponse, VersionDetailResponse, VersionDiffResponse,
    VersionRecordResponse, ZoneVersionResponse,
};
pub use zone::{
    CreateZoneRequest, ExportZoneFileResponse, GetZoneResponse, GetZonesFilter, NotifyZoneRequest,
    SecondaryStatusResponse, UpdateZonePatch, ZoneDetailResponse, ZoneResponse, ZoneStatusResponse,
};
