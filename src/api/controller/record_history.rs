use super::{
    auth,
    internal::{get_param, utils::json_response, Method, Request, Response, Router, StatusCode},
};
use crate::{
    api::{dto::GetRecordHistoryResponse, service::record_history::RecordHistoryService},
    database::DATABASE_POOL,
};
use serde_json::json;

pub(crate) struct RecordHistoryController;

impl RecordHistoryController {
    pub(crate) async fn router() -> Router {
        let mut router = Router::new();

        router.register_endpoint_with_middleware(
            Method::GET,
            "/records/:id/histories",
            RecordHistoryController::get_record_histories,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::DELETE,
            "/records/:record_id/histories/:history_id",
            RecordHistoryController::delete_record_history,
            auth::middleware::auth_middleware,
        );

        router
    }

    async fn get_record_histories(request: Request) -> Response {
        let record_id = match get_param::<i32>(&request, "/records/:id/histories", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record_histories =
            match RecordHistoryService::get_record_histories(&DATABASE_POOL, record_id) {
                Ok(record_histories) => record_histories,
                Err(err) => {
                    let json_body = json!({ "error": err });
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
            "/records/:record_id/histories/:history_id",
            "history_id",
        ) {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing history_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        if RecordHistoryService::delete_record_history(&DATABASE_POOL, history_id).is_err() {
            let json_body = json!({ "error": "Failed to delete record history" });
            return json_response(json_body, StatusCode::BAD_REQUEST);
        }

        let json_body = json!({ "message": "Record history deleted successfully" });
        json_response(json_body, StatusCode::OK)
    }
}
