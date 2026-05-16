use crate::api::{
    dto::{CreateRecordRequest, GetRecordResponse},
    error::ApiError,
    middleware::body_parser::JsonBody,
};
use crate::database::model::record::RecordType;
use crate::service::error::ServiceError;
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

pub struct RecordApi;

impl RecordApi {
    pub async fn routes() -> Router {
        Router::new()
            .route("/records", routing::get(Self::get_records))
            .route(
                "/records/{name}/{record_type}",
                routing::get(Self::get_record),
            )
            .route("/records", routing::post(Self::create_record))
            .route(
                "/records/{name}/{record_type}",
                routing::put(Self::update_record),
            )
            .route(
                "/records/{name}/{record_type}",
                routing::delete(Self::delete_record),
            )
    }

    async fn get_records(Query(query): Query<GetRecordsQuery>) -> impl IntoResponse {
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

    async fn get_record(Path(params): Path<GetRecordParam>) -> impl IntoResponse {
        let name = params.name;
        let record_type = match RecordType::from_str(&params.record_type) {
            Ok(record_type) => record_type,
            Err(_) => {
                return ApiError::from(ServiceError::BadRequest(format!(
                    "Invalid record type: {}",
                    params.record_type
                )))
                .into_response();
            }
        };

        let raw_record =
            match RecordService::get(None, &name, &record_type, None, None, false).await {
                Ok(record) => record,
                Err(err) => return ApiError::from(err).into_response(),
            };

        let record = GetRecordResponse::from_record(&raw_record);

        let json_body = json!({ "record": record });
        (StatusCode::OK, Json(json_body)).into_response()
    }

    async fn create_record(JsonBody(body): JsonBody<CreateRecordRequest>) -> impl IntoResponse {
        let raw_record = match RecordService::create(&body).await {
            Ok(record) => record,
            Err(err) => return ApiError::from(err).into_response(),
        };

        let record = GetRecordResponse::from_record(&raw_record);

        let json_body = json!({ "record": record });
        (StatusCode::CREATED, Json(json_body)).into_response()
    }

    async fn update_record(
        Path(params): Path<UpdateRecordParam>,
        Json(body): Json<CreateRecordRequest>,
    ) -> impl IntoResponse {
        let name = params.name;
        let record_type = params.record_type;

        let raw_record = match RecordService::update(&name, &record_type, &body).await {
            Ok(record) => record,
            Err(err) => return ApiError::from(err).into_response(),
        };

        let record = GetRecordResponse::from_record(&raw_record);

        let json_body = json!({ "record": record });
        (StatusCode::OK, Json(json_body)).into_response()
    }

    async fn delete_record(Path(params): Path<DeleteRecordParam>) -> impl IntoResponse {
        let name = params.name;
        let record_type = params.record_type;

        match RecordService::delete(&name, &record_type).await {
            Ok(_) => {
                let json_body = json!({ "message": "Record deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => ApiError::from(err).into_response(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GetRecordsQuery {
    zone_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GetRecordParam {
    name: String,
    record_type: String,
}

#[derive(Debug, Deserialize)]
struct UpdateRecordParam {
    name: String,
    record_type: String,
}

#[derive(Debug, Deserialize)]
struct DeleteRecordParam {
    name: String,
    record_type: String,
}
