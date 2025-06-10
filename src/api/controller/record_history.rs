use axum::{extract::Path, http::StatusCode, response::IntoResponse, routing, Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::{
    api::{dto::GetRecordHistoryResponse, service::record_history::RecordHistoryService},
    database::DATABASE_POOL,
};

pub struct RecordHistoryController;

impl RecordHistoryController {
    pub async fn routes() -> Router {
        Router::new()
            .route(
                "/records/{id}/histories",
                routing::get(RecordHistoryController::get_record_histories),
            )
            .route(
                "/records/{record_id}/histories/{history_id}",
                routing::delete(RecordHistoryController::delete_record_history),
            )
    }

    async fn get_record_histories(
        Path(params): Path<GetRecordHistoriesParam>,
    ) -> impl IntoResponse {
        let record_id = params.id;

        let raw_record_histories =
            match RecordHistoryService::get_record_histories(&DATABASE_POOL, record_id) {
                Ok(record_histories) => record_histories,
                Err(err) => {
                    let json_body = json!({ "error": err });
                    return (StatusCode::BAD_REQUEST, Json(json_body));
                }
            };

        let record_histories = raw_record_histories
            .iter()
            .map(GetRecordHistoryResponse::from_record_history)
            .collect::<Vec<GetRecordHistoryResponse>>();

        let json_body = json!({ "record_histories": record_histories });
        (StatusCode::OK, Json(json_body))
    }

    async fn delete_record_history(
        Path(param): Path<DeleteRecordHistoryParam>,
    ) -> impl IntoResponse {
        let history_id = param.history_id;

        if RecordHistoryService::delete_record_history(&DATABASE_POOL, history_id).is_err() {
            let json_body = json!({ "error": "Failed to delete record history" });
            return (StatusCode::BAD_REQUEST, Json(json_body));
        }

        let json_body = json!({ "message": "Record history deleted successfully" });
        (StatusCode::OK, Json(json_body))
    }
}
#[derive(Debug, Deserialize)]
struct GetRecordHistoriesParam {
    id: i32,
}

#[derive(Debug, Deserialize)]
struct DeleteRecordHistoryParam {
    _record_id: i32,
    history_id: i32,
}
