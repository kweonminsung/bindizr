//! Service-layer request and response payloads, grouped by the entity they
//! belong to. Re-exported flat so callers keep naming them `types::X`.
//!
//! These are the wire contract of every front end, not just HTTP: the daemon
//! socket carries the same shapes, so a response type the CLI reads back
//! derives `Deserialize` too.

mod common;
mod external_dns;
mod import;
mod pagination;
mod record;
mod snapshot;
mod token;
mod token_policy;
mod tsig;
mod zone;

pub use common::{ErrorResponse, HealthResponse, MessageResponse};
pub use external_dns::{
    ExternalDnsChangesRequest, ExternalDnsChangesResponse, ExternalDnsRecordItem,
    ExternalDnsRecordsResponse, ExternalDnsRrset, ExternalDnsRrsetUpdate, ExternalDnsZonesResponse,
};
pub use import::{ImportMode, ImportSummary, ImportZoneFileRequest, ImportZoneFileResponse};
pub use pagination::{PaginatedResponse, Pagination};
pub(crate) use record::display_record_value_request;
pub use record::{
    BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, GetRecordResponse,
    GetRecordsFilter, RecordItem, RecordResponse, RecordValueRequest, UpdateRecordPatch,
};
pub use snapshot::{
    RecordDiff, RecordDiffEntry, RecordDiffSummary, RecordDiffValue, RollbackSummary,
    RollbackZoneRequest, RollbackZoneResponse, SnapshotDetailResponse, SnapshotDiffResponse,
    SnapshotRecordResponse, ZoneSnapshotResponse,
};
pub use token::GetTokenResponse;
pub use token_policy::{
    CreateZoneTokenPolicyRequest, GetZoneTokenPolicyResponse, ZoneTokenPolicyListResponse,
    ZoneTokenPolicyResponse,
};
pub use tsig::{
    CreateTsigKeyRequest, CreateZoneTsigPolicyRequest, GetTsigKeyResponse,
    GetZoneTsigPolicyResponse, TsigKeyListResponse, TsigKeyResponse, ZoneTsigPolicyListResponse,
    ZoneTsigPolicyResponse,
};
pub use zone::{
    CreateZoneRequest, ExportZoneFileResponse, GetZoneResponse, GetZonesFilter, NotifyZoneRequest,
    SecondaryStatusResponse, UpdateZonePatch, ZoneDetailResponse, ZoneResponse, ZoneStatusResponse,
};
