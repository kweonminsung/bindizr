use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde::Deserialize;
use serde_json::json;

use crate::api::{dto::GetRecordHistoryResponse, service::record_history::RecordHistoryService};

pub struct RecordHistoryController;

impl RecordHistoryController {
    pub async fn routes() -> Router {
        Router::new()
            .route(
                "/records/{name}/{record_type}/histories",
                routing::get(RecordHistoryController::get_record_histories),
            )
            .route(
                "/records/{record_name}/{record_type}/histories/{history_id}",
                routing::delete(RecordHistoryController::delete_record_history),
            )
    }

    async fn get_record_histories(
        Path(params): Path<GetRecordHistoriesParam>,
    ) -> impl IntoResponse {
        let name = params.name;
        let record_type = params.record_type;

        let raw_record_histories =
            match RecordHistoryService::get_record_histories(&name, &record_type).await {
                Ok(record_histories) => record_histories,
                Err(err) => return err.into_response(),
            };

        let record_histories = raw_record_histories
            .iter()
            .map(GetRecordHistoryResponse::from_record_history)
            .collect::<Vec<GetRecordHistoryResponse>>();

        let json_body = json!({ "record_histories": record_histories });
        (StatusCode::OK, Json(json_body)).into_response()
    }

    async fn delete_record_history(
        Path(param): Path<DeleteRecordHistoryParam>,
    ) -> impl IntoResponse {
        let history_id = param.history_id;

        match RecordHistoryService::delete_record_history(history_id).await {
            Ok(_) => {
                let json_body = json!({ "message": "Record history deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GetRecordHistoriesParam {
    name: String,
    record_type: String,
}

#[derive(Debug, Deserialize)]
struct DeleteRecordHistoryParam {
    _record_name: String,
    _record_type: String,
    history_id: i32,
}
