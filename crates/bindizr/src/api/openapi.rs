use utoipa::{
    Modify, OpenApi,
    openapi::security::{Http, HttpAuthScheme, SecurityScheme},
};

use super::types::{
    BulkRecordItem, BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest,
    CreateTsigKeyRequest, CreateZoneRequest, CreateZoneTsigPolicyRequest, ErrorResponse,
    GetRecordResponse, GetTsigKeyResponse, GetZoneResponse, GetZoneTsigPolicyResponse, ImportMode,
    ImportSummary, ImportZoneFileRequest, ImportZoneFileResponse, MessageResponse,
    NotifyZoneRequest, Pagination, RecordDiff, RecordDiffEntry, RecordDiffSummary, RecordDiffValue,
    RecordListResponse, RecordResponse, RecordValueRequest, RollbackSummary, RollbackZoneRequest,
    RollbackZoneResponse, SecondaryStatusResponse, SnapshotDetailResponse, SnapshotDiffResponse,
    SnapshotListResponse, SnapshotRecordResponse, TsigKeyListResponse, TsigKeyResponse,
    UpdateRecordRequest, ZoneDetailResponse, ZoneListResponse, ZoneResponse, ZoneSnapshotResponse,
    ZoneStatusResponse, ZoneTsigPolicyListResponse, ZoneTsigPolicyResponse,
};

/// OpenAPI document for the HTTP API (debug builds only).
#[derive(OpenApi)]
#[openapi(
    paths(
        super::zone::get_zones,
        super::zone::get_zone,
        super::zone::create_zone,
        super::zone::update_zone,
        super::zone::delete_zone,
        super::record::get_records,
        super::record::get_record,
        super::record::create_record,
        super::record::update_record,
        super::record::delete_record,
        super::record::create_records_bulk,
        super::zone::import_zone,
        super::zone::export_zone,
        super::zone::list_zone_snapshots,
        super::zone::get_zone_snapshot,
        super::zone::diff_zone_snapshots,
        super::zone::rollback_zone,
        super::zone::get_zone_status,
        super::notify::notify_zones,
        super::tsig_key::get_tsig_keys,
        super::tsig_key::create_tsig_key,
        super::tsig_key::get_tsig_key,
        super::tsig_key::delete_tsig_key,
        super::tsig_key::get_zone_tsig_policies,
        super::tsig_key::create_zone_tsig_policy,
        super::tsig_key::delete_zone_tsig_policy
    ),
    components(schemas(
        BulkRecordItem,
        BulkRecordsResponse,
        CreateBulkRecordsRequest,
        CreateRecordRequest,
        CreateTsigKeyRequest,
        CreateZoneRequest,
        CreateZoneTsigPolicyRequest,
        ErrorResponse,
        GetRecordResponse,
        GetTsigKeyResponse,
        GetZoneResponse,
        GetZoneTsigPolicyResponse,
        ImportMode,
        ImportSummary,
        ImportZoneFileRequest,
        ImportZoneFileResponse,
        MessageResponse,
        NotifyZoneRequest,
        Pagination,
        RecordDiff,
        RecordDiffEntry,
        RecordDiffSummary,
        RecordDiffValue,
        RecordListResponse,
        RecordResponse,
        RecordValueRequest,
        RollbackSummary,
        RollbackZoneRequest,
        RollbackZoneResponse,
        SecondaryStatusResponse,
        SnapshotDetailResponse,
        SnapshotDiffResponse,
        SnapshotListResponse,
        SnapshotRecordResponse,
        TsigKeyListResponse,
        TsigKeyResponse,
        UpdateRecordRequest,
        ZoneDetailResponse,
        ZoneListResponse,
        ZoneResponse,
        ZoneSnapshotResponse,
        ZoneStatusResponse,
        ZoneTsigPolicyListResponse,
        ZoneTsigPolicyResponse
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Zone", description = "Manage DNS zones including creation, update, deletion, and retrieval."),
        (name = "Record", description = "Manage DNS records including creation, update, deletion, and retrieval."),
        (name = "Notify", description = "Send DNS NOTIFY messages to secondary servers."),
        (name = "TSIG", description = "Manage TSIG keys and per-zone TSIG policies for nsupdate authentication.")
    ),
    info(
        title = "Bindizr HTTP API",
        version = env!("CARGO_PKG_VERSION"),
        description = "This is the API documentation for Bindizr",
        contact(email = "kevin136583@gmail.com"),
        license(name = "Apache 2.0", url = "http://www.apache.org/licenses/LICENSE-2.0.html")
    )
)]
pub(crate) struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
        }
    }
}
