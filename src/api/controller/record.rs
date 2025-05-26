use super::{
    auth,
    internal::{
        get_body, get_param, get_query, utils::json_response, Method, Request, Response, Router,
        StatusCode,
    },
};
use crate::{
    api::{
        dto::{CreateRecordRequest, GetRecordResponse},
        service::record::RecordService,
    },
    database::DATABASE_POOL,
};
use serde_json::json;

pub struct RecordController;

impl RecordController {
    pub async fn router() -> Router {
        let mut router = Router::new();

        router.register_endpoint(Method::GET, "/records", RecordController::get_records);
        router.register_endpoint(Method::GET, "/records/:id", RecordController::get_record);
        router.register_endpoint_with_middleware(
            Method::POST,
            "/records",
            RecordController::create_record,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::PUT,
            "/records/:id",
            RecordController::update_record,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::DELETE,
            "/records/:id",
            RecordController::delete_record,
            auth::middleware::auth_middleware,
        );

        router
    }

    async fn get_records(request: Request) -> Response {
        let zone_id = get_query::<i32>(&request, "zone_id");

        let raw_records = match RecordService::get_records(&DATABASE_POOL, zone_id) {
            Ok(records) => records,
            Err(err) => {
                let json_body = json!({ "error": err });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let records = raw_records
            .iter()
            .map(|record| GetRecordResponse::from_record(record))
            .collect::<Vec<GetRecordResponse>>();

        let json_body = json!({ "records": records });
        json_response(json_body, StatusCode::OK)
    }

    async fn get_record(request: Request) -> Response {
        let record_id = match get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record = match RecordService::get_record(&DATABASE_POOL, record_id) {
            Ok(record) => record,
            Err(err) => {
                let json_body = json!({ "error": err });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);

        let json_body = json!({ "record": record });
        json_response(json_body, StatusCode::OK)
    }

    async fn create_record(request: Request) -> Response {
        let body = match get_body::<CreateRecordRequest>(request).await {
            Ok(b) => b,
            Err(err) => {
                eprintln!("Error parsing request body: {}", err);
                let json_body = json!({ "error": "Invalid request body" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record = match RecordService::create_record(&DATABASE_POOL, &body) {
            Ok(record) => record,
            Err(err) => {
                let json_body = json!({ "error": err });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);
        let json_body = json!({ "record": record });

        json_response(json_body, StatusCode::OK)
    }

    async fn update_record(request: Request) -> Response {
        let record_id = match get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let body = match get_body::<CreateRecordRequest>(request).await {
            Ok(b) => b,
            Err(err) => {
                eprintln!("Error parsing request body: {}", err);
                let json_body = json!({ "error": "Invalid request body" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record = match RecordService::update_record(&DATABASE_POOL, record_id, &body) {
            Ok(record) => record,
            Err(err) => {
                let json_body = json!({ "error": err });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);
        let json_body = json!({ "record": record });

        json_response(json_body, StatusCode::OK)
    }

    async fn delete_record(request: Request) -> Response {
        let record_id = match get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        match RecordService::delete_record(&DATABASE_POOL, record_id) {
            Ok(_) => {
                let json_body = json!({ "message": "Record deleted successfully" });
                json_response(json_body, StatusCode::OK)
            }
            Err(err) => {
                let json_body = json!({ "error": err });
                json_response(json_body, StatusCode::BAD_REQUEST)
            }
        }
    }
}
