use crate::api::{
    error::ApiError,
    middleware::body_parser::JsonBody,
    types::{
        CreateRecordRequest, ErrorResponse, GetRecordResponse, MessageResponse, RecordListResponse,
        RecordResponse, UpdateRecordRequest,
    },
};
use crate::service::record::RecordService;
use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing,
};
use serde::Deserialize;
use serde_json::json;

pub(crate) struct RecordApi;

impl RecordApi {
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/records", routing::get(get_records))
            .route("/records/{record_id}", routing::get(get_record))
            .route("/records", routing::post(create_record))
            .route("/records/{record_id}", routing::put(update_record))
            .route("/records/{record_id}", routing::delete(delete_record))
    }
}

#[utoipa::path(
        get,
        path = "/records",
        tag = "Record",
        summary = "List all DNS records",
        params(
            ("zone_name" = Option<String>, Query, description = "The name of the DNS zone to filter records by.")
        ),
        responses(
            (status = 200, description = "A list of DNS records", body = RecordListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_records(Query(query): Query<GetRecordsQuery>) -> impl IntoResponse {
    let zone_name = query.zone_name;

    let raw_records = match RecordService::list(zone_name).await {
        Ok(records) => records,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let records = raw_records
        .iter()
        .map(GetRecordResponse::from_record)
        .collect::<Vec<GetRecordResponse>>();

    let json_body = json!({ "records": records });
    (StatusCode::OK, Json(json_body)).into_response()
}

#[utoipa::path(
        get,
        path = "/records/{record_id}",
        tag = "Record",
        summary = "Get a specific DNS record",
        params(
            ("record_id" = i32, Path, description = "The ID of the DNS record to retrieve.")
        ),
        responses(
            (status = 200, description = "Details of the DNS record", body = RecordResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_record(Path(params): Path<GetRecordParam>) -> impl IntoResponse {
    let raw_record = match RecordService::get_by_id(params.record_id).await {
        Ok(record) => record,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let record = GetRecordResponse::from_record(&raw_record);

    let json_body = json!({ "record": record });
    (StatusCode::OK, Json(json_body)).into_response()
}

#[utoipa::path(
        post,
        path = "/records",
        tag = "Record",
        summary = "Create a new DNS record",
        request_body = CreateRecordRequest,
        responses(
            (status = 201, description = "DNS record created successfully", body = RecordResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_record(
    JsonBody(body): JsonBody<CreateRecordRequest>,
) -> impl IntoResponse {
    let raw_record = match RecordService::create(&body).await {
        Ok(record) => record,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let record = GetRecordResponse::from_record(&raw_record);

    let json_body = json!({ "record": record });
    (StatusCode::CREATED, Json(json_body)).into_response()
}

#[utoipa::path(
        put,
        path = "/records/{record_id}",
        tag = "Record",
        summary = "Update a specific DNS record",
        params(
            ("record_id" = i32, Path, description = "The ID of the DNS record to update.")
        ),
        request_body = UpdateRecordRequest,
        responses(
            (status = 200, description = "DNS record updated successfully", body = RecordResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn update_record(
    Path(params): Path<UpdateRecordParam>,
    JsonBody(body): JsonBody<UpdateRecordRequest>,
) -> impl IntoResponse {
    let raw_record = match RecordService::update_by_id(params.record_id, &body).await {
        Ok(record) => record,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let record = GetRecordResponse::from_record(&raw_record);

    let json_body = json!({ "record": record });
    (StatusCode::OK, Json(json_body)).into_response()
}

#[utoipa::path(
        delete,
        path = "/records/{record_id}",
        tag = "Record",
        summary = "Delete a specific DNS record",
        params(
            ("record_id" = i32, Path, description = "The ID of the DNS record to delete.")
        ),
        responses(
            (status = 200, description = "DNS record deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_record(Path(params): Path<DeleteRecordParam>) -> impl IntoResponse {
    match RecordService::delete_by_id(params.record_id).await {
        Ok(_) => {
            let json_body = json!({ "message": "Record deleted successfully" });
            (StatusCode::OK, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct GetRecordsQuery {
    zone_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GetRecordParam {
    record_id: i32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateRecordParam {
    record_id: i32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteRecordParam {
    record_id: i32,
}
