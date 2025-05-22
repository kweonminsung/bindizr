use serde_json::json;

use crate::{
    api::{dto::GetRecordHistoryResponse, service::record_history::RecordHistoryService},
    database::DATABASE_POOL,
};

use super::internal::{
    get_param, utils::json_response, Method, Request, Response, Router, StatusCode,
};

pub struct RecordHistoryController;

impl RecordHistoryController {
    pub async fn router() -> Router {
        let mut router = Router::new();

        // register routes
        router.register_endpoint(
            Method::GET,
            "/records/:id/history",
            RecordHistoryController::get_record_histories,
        );
        router.register_endpoint(
            Method::DELETE,
            "/records/:record_id/:history/:history_id",
            RecordHistoryController::delete_record_history,
        );

        router
    }

    async fn get_record_histories(request: Request) -> Response {
        let record_id = match get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record_histories =
            match RecordHistoryService::get_record_histories(&DATABASE_POOL, record_id) {
                Ok(record_histories) => record_histories,
                Err(_) => {
                    let json_body = json!({ "error": "Record not found" });
                    return json_response(json_body, StatusCode::BAD_REQUEST);
                }
            };

        let record_histories = raw_record_histories
            .iter()
            .map(|record_history| GetRecordHistoryResponse::from_record_history(record_history))
            .collect::<Vec<GetRecordHistoryResponse>>();

        let json_body = json!({ "record_histories": record_histories });
        json_response(json_body, StatusCode::OK)
    }

    async fn delete_record_history(request: Request) -> Response {
        let history_id = match get_param::<i32>(
            &request,
            "/records/:record_id/history/:history_id",
            "history_id",
        ) {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing history_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        match RecordHistoryService::delete_record_history(&DATABASE_POOL, history_id) {
            Ok(_) => {
                let json_body = json!({ "message": "Record history deleted successfully" });
                json_response(json_body, StatusCode::OK)
            }
            Err(_) => {
                let json_body = json!({ "error": "Failed to delete record history" });
                json_response(json_body, StatusCode::BAD_REQUEST)
            }
        }
    }
}
