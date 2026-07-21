use utoipa::{
    Modify, OpenApi,
    openapi::security::{Http, HttpAuthScheme, SecurityScheme},
};

use super::types::{
    BulkRecordItem, BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest,
    CreateZoneRequest, ErrorResponse, GetRecordResponse, GetZoneResponse, ImportMode,
    ImportSummary, ImportZoneFileRequest, ImportZoneFileResponse, MessageResponse,
    NotifyZoneRequest, Pagination, RecordListResponse, RecordResponse, RecordValueRequest,
    RollbackSummary, RollbackZoneRequest, RollbackZoneResponse, SecondaryStatusResponse,
    SnapshotDetailResponse, SnapshotListResponse, SnapshotRecordResponse, UpdateRecordRequest,
    ZoneDetailResponse, ZoneListResponse, ZoneResponse, ZoneSnapshotResponse, ZoneStatusResponse,
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
        super::zone::list_zone_snapshots,
        super::zone::get_zone_snapshot,
        super::zone::rollback_zone,
        super::zone::get_zone_status,
        super::notify::notify_zones
    ),
    components(schemas(
        BulkRecordItem,
        BulkRecordsResponse,
        CreateBulkRecordsRequest,
        CreateRecordRequest,
        CreateZoneRequest,
        ErrorResponse,
        GetRecordResponse,
        GetZoneResponse,
        ImportMode,
        ImportSummary,
        ImportZoneFileRequest,
        ImportZoneFileResponse,
        MessageResponse,
        NotifyZoneRequest,
        Pagination,
        RecordListResponse,
        RecordResponse,
        RecordValueRequest,
        RollbackSummary,
        RollbackZoneRequest,
        RollbackZoneResponse,
        SecondaryStatusResponse,
        SnapshotDetailResponse,
        SnapshotListResponse,
        SnapshotRecordResponse,
        UpdateRecordRequest,
        ZoneDetailResponse,
        ZoneListResponse,
        ZoneResponse,
        ZoneSnapshotResponse,
        ZoneStatusResponse
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Zone", description = "Manage DNS zones including creation, update, deletion, and retrieval."),
        (name = "Record", description = "Manage DNS records including creation, update, deletion, and retrieval."),
        (name = "Notify", description = "Send DNS NOTIFY messages to secondary servers.")
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
