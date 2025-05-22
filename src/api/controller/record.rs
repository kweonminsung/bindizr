use super::internal::{Method, Request, Response, Router, StatusCode};
use crate::{
    api::{
        dto::{CreateRecordRequest, GetRecordResponse},
        service::ApiService,
        utils,
    },
    database::DATABASE_POOL,
};
use serde_json::json;

pub struct RecordController;

impl RecordController {
    pub async fn router() -> Router {
        let mut router = Router::new();

        // register routes
        router.register_endpoint(Method::GET, "/records", RecordController::get_records);
        router.register_endpoint(Method::GET, "/records/:id", RecordController::get_record);
        router.register_endpoint(Method::POST, "/records", RecordController::create_record);
        router.register_endpoint(Method::PUT, "/records/:id", RecordController::update_record);
        router.register_endpoint(
            Method::DELETE,
            "/records/:id",
            RecordController::delete_record,
        );

        router
    }

    async fn get_records(request: Request) -> Response {
        let zone_id = utils::get_query::<i32>(&request, "zone_id");

        let raw_records = ApiService::get_records(&DATABASE_POOL, zone_id);

        let records = raw_records
            .iter()
            .map(|record| GetRecordResponse::from_record(record))
            .collect::<Vec<GetRecordResponse>>();

        let json_body = json!({ "records": records });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn get_record(request: Request) -> Response {
        let record_id = match utils::get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record = match ApiService::get_record(&DATABASE_POOL, record_id) {
            Ok(record) => record,
            Err(_) => {
                let json_body = json!({ "error": "Record not found" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);

        let json_body = json!({ "record": record });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn create_record(request: Request) -> Response {
        let body = match utils::get_body::<CreateRecordRequest>(request).await {
            Ok(b) => b,
            Err(_) => {
                let json_body = json!({ "error": "Invalid request body" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record = match ApiService::create_record(&DATABASE_POOL, &body) {
            Ok(record) => record,
            Err(_) => {
                let json_body = json!({ "error": "Failed to create record" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);
        let json_body = json!({ "record": record });

        utils::json_response(json_body, StatusCode::OK)
    }

    async fn update_record(request: Request) -> Response {
        let record_id = match utils::get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let body = match utils::get_body::<CreateRecordRequest>(request).await {
            Ok(b) => b,
            Err(_) => {
                let json_body = json!({ "error": "Invalid request body" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record = match ApiService::update_record(&DATABASE_POOL, record_id, &body) {
            Ok(record) => record,
            Err(_) => {
                let json_body = json!({ "error": "Failed to update record" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);
        let json_body = json!({ "record": record });

        utils::json_response(json_body, StatusCode::OK)
    }

    async fn delete_record(request: Request) -> Response {
        let record_id = match utils::get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        match ApiService::delete_record(&DATABASE_POOL, record_id) {
            Ok(_) => {
                let json_body = json!({ "message": "Record deleted successfully" });
                utils::json_response(json_body, StatusCode::OK)
            }
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to delete record: {}", err) });
                utils::json_response(json_body, StatusCode::BAD_REQUEST)
            }
        }
    }
}
