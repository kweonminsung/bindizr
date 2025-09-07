use crate::api::{
    controller::middleware::body_parser::JsonBody,
    dto::{CreateRecordRequest, GetRecordResponse},
    service::record::RecordService,
};
use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing,
};
use serde::Deserialize;
use serde_json::json;

pub struct RecordController;

impl RecordController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/records", routing::get(Self::get_records))
            .route("/records/{id}", routing::get(Self::get_record))
            .route("/records", routing::post(Self::create_record))
            .route("/records/{id}", routing::put(Self::update_record))
            .route("/records/{id}", routing::delete(Self::delete_record))
    }

    async fn get_records(Query(query): Query<GetRecordsQuery>) -> impl IntoResponse {
        let zone_id = query.zone_id;

        let raw_records = match RecordService::get_records(zone_id).await {
            Ok(records) => records,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body));
            }
        };

        let records = raw_records
            .iter()
            .map(GetRecordResponse::from_record)
            .collect::<Vec<GetRecordResponse>>();

        let json_body = json!({ "records": records });
        (StatusCode::OK, Json(json_body))
    }

    async fn get_record(Path(params): Path<GetRecordParam>) -> impl IntoResponse {
        let record_id = params.id;

        let raw_record = match RecordService::get_record(record_id).await {
            Ok(record) => record,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body));
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);

        let json_body = json!({ "record": record });
        (StatusCode::OK, Json(json_body))
    }

    async fn create_record(JsonBody(body): JsonBody<CreateRecordRequest>) -> impl IntoResponse {
        let raw_record = match RecordService::create_record(&body).await {
            Ok(record) => record,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body));
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);

        let json_body = json!({ "record": record });
        (StatusCode::CREATED, Json(json_body))
    }

    async fn update_record(
        Path(params): Path<UpdateRecordParam>,
        Json(body): Json<CreateRecordRequest>,
    ) -> impl IntoResponse {
        let record_id = params.id;

        let raw_record = match RecordService::update_record(record_id, &body).await {
            Ok(record) => record,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body));
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);

        let json_body = json!({ "record": record });
        (StatusCode::OK, Json(json_body))
    }

    async fn delete_record(Path(params): Path<DeleteRecordParam>) -> impl IntoResponse {
        let record_id = params.id;

        match RecordService::delete_record(record_id).await {
            Ok(_) => {
                let json_body = json!({ "message": "Record deleted successfully" });
                (StatusCode::OK, Json(json_body))
            }
            Err(err) => {
                let json_body = json!({ "error": err });
                (StatusCode::BAD_REQUEST, Json(json_body))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct GetRecordsQuery {
    zone_id: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct GetRecordParam {
    id: i32,
}

#[derive(Debug, Deserialize)]
struct UpdateRecordParam {
    id: i32,
}

#[derive(Debug, Deserialize)]
struct DeleteRecordParam {
    id: i32,
}
