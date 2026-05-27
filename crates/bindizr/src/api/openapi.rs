use utoipa::{
    Modify, OpenApi,
    openapi::security::{Http, HttpAuthScheme, SecurityScheme},
};

use super::dto::{
    CreateRecordRequest, CreateZoneRequest, ErrorResponse, GetRecordResponse, GetZoneResponse,
    MessageResponse, RecordListResponse, RecordResponse, RecordValueRequest, UpdateRecordRequest,
    ZoneDetailResponse, ZoneListResponse, ZoneResponse,
};

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
        super::record::delete_record
    ),
    components(schemas(
        CreateRecordRequest,
        CreateZoneRequest,
        ErrorResponse,
        GetRecordResponse,
        GetZoneResponse,
        MessageResponse,
        RecordListResponse,
        RecordResponse,
        RecordValueRequest,
        UpdateRecordRequest,
        ZoneDetailResponse,
        ZoneListResponse,
        ZoneResponse
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Zone", description = "Manage DNS zones including creation, update, deletion, and retrieval."),
        (name = "Record", description = "Manage DNS records including creation, update, deletion, and retrieval.")
    ),
    info(
        title = "Bindizr HTTP API",
        version = env!("CARGO_PKG_VERSION"),
        description = "This is the API documentation for Bindizr",
        contact(email = "kevin136583@gmail.com"),
        license(name = "Apache 2.0", url = "http://www.apache.org/licenses/LICENSE-2.0.html")
    )
)]
pub struct ApiDoc;

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
