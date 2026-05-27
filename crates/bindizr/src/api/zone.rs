use crate::api::{
    error::ApiError,
    middleware::body_parser::JsonBody,
    types::{
        CreateZoneRequest, ErrorResponse, GetRecordResponse, GetZoneResponse, MessageResponse,
        ZoneDetailResponse, ZoneListResponse, ZoneResponse,
    },
};
use crate::service::{record::RecordService, zone::ZoneService};
use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing,
};
use serde::Deserialize;
use serde_json::json;

pub(crate) struct ZoneApi;

impl ZoneApi {
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/zones", routing::get(get_zones))
            .route("/zones/{name}", routing::get(get_zone))
            .route("/zones", routing::post(create_zone))
            .route("/zones/{name}", routing::put(update_zone))
            .route("/zones/{name}", routing::delete(delete_zone))
    }
}

#[utoipa::path(
        get,
        path = "/zones",
        tag = "Zone",
        summary = "List all DNS zones",
        responses(
            (status = 200, description = "A list of DNS zones", body = ZoneListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_zones() -> impl IntoResponse {
    match ZoneService::list().await {
        Ok(zones) => {
            let zones = zones
                .iter()
                .map(GetZoneResponse::from_zone)
                .collect::<Vec<GetZoneResponse>>();
            let json_body = json!({ "zones": zones });
            (StatusCode::OK, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[utoipa::path(
        get,
        path = "/zones/{name}",
        tag = "Zone",
        summary = "Get a specific DNS zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to retrieve."),
            ("records" = Option<bool>, Query, description = "Whether to include records for the DNS zone.")
        ),
        responses(
            (status = 200, description = "Details of the DNS zone", body = ZoneDetailResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_zone(
    Path(params): Path<GetZoneParam>,
    Query(query): Query<GetZoneQuery>,
) -> impl IntoResponse {
    let zone_name = params.name;
    let records_query = query.records;

    let raw_zone = match ZoneService::get_by_name(&zone_name).await {
        Ok(zone) => zone,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let raw_records = match records_query {
        Some(true) => match RecordService::list(Some(raw_zone.name.clone())).await {
            Ok(records) => records,
            Err(err) => return ApiError::from(err).into_response(),
        },
        _ => vec![],
    };
    let records = raw_records
        .iter()
        .map(GetRecordResponse::from_record)
        .collect::<Vec<GetRecordResponse>>();

    let zone = GetZoneResponse::from_zone(&raw_zone);
    let json_body = json!({ "zone": zone, "records": records });
    (StatusCode::OK, Json(json_body)).into_response()
}

#[utoipa::path(
        post,
        path = "/zones",
        tag = "Zone",
        summary = "Create a new DNS zone",
        request_body = CreateZoneRequest,
        responses(
            (status = 201, description = "DNS zone created successfully", body = ZoneResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_zone(JsonBody(body): JsonBody<CreateZoneRequest>) -> impl IntoResponse {
    match ZoneService::create(&body).await {
        Ok(zone) => {
            let zone = GetZoneResponse::from_zone(&zone);
            let json_body = json!({ "zone": zone });
            (StatusCode::CREATED, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[utoipa::path(
        put,
        path = "/zones/{name}",
        tag = "Zone",
        summary = "Update a specific DNS zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to update.")
        ),
        request_body = CreateZoneRequest,
        responses(
            (status = 200, description = "DNS zone updated successfully", body = ZoneResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn update_zone(
    Path(params): Path<UpdateZoneParam>,
    JsonBody(body): JsonBody<CreateZoneRequest>,
) -> impl IntoResponse {
    let zone_name = params.name;

    match ZoneService::update(&zone_name, &body).await {
        Ok(zone) => {
            let zone = GetZoneResponse::from_zone(&zone);
            let json_body = json!({ "zone": zone });
            (StatusCode::OK, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[utoipa::path(
        delete,
        path = "/zones/{name}",
        tag = "Zone",
        summary = "Delete a specific DNS zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to delete.")
        ),
        responses(
            (status = 200, description = "DNS zone deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_zone(Path(params): Path<DeleteZoneParam>) -> impl IntoResponse {
    let zone_name = params.name;

    match ZoneService::delete(&zone_name).await {
        Ok(_) => {
            let json_body = json!({ "message": "Zone deleted successfully" });
            (StatusCode::OK, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct GetZoneParam {
    name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GetZoneQuery {
    records: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateZoneParam {
    name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteZoneParam {
    name: String,
}
