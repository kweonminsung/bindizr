use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde::Deserialize;
use serde_json::json;

use crate::api::{dto::GetZoneHistoryResponse, service::zone_history::ZoneHistoryService};

pub struct ZoneHistoryController;

impl ZoneHistoryController {
    pub async fn routes() -> Router {
        Router::new()
            .route(
                "/zones/{id}/histories",
                routing::get(Self::get_zone_histories),
            )
            .route(
                "/zones/{zone_id}/histories/{history_id}",
                routing::delete(Self::delete_zone_history),
            )
    }

    async fn get_zone_histories(Path(params): Path<GetZoneHistoriesParam>) -> impl IntoResponse {
        let zone_id = params.id;

        let raw_zone_histories = match ZoneHistoryService::get_zone_histories(zone_id).await {
            Ok(zone_histories) => zone_histories,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body));
            }
        };

        let zone_histories = raw_zone_histories
            .iter()
            .map(GetZoneHistoryResponse::from_zone_history)
            .collect::<Vec<GetZoneHistoryResponse>>();

        let json_body = json!({ "zone_histories": zone_histories });
        (StatusCode::OK, Json(json_body))
    }

    async fn delete_zone_history(Path(params): Path<DeleteZoneHistoryParam>) -> impl IntoResponse {
        let history_id = params.history_id;

        match ZoneHistoryService::delete_zone_history(history_id).await {
            Ok(_) => {
                let json_body = json!({ "message": "Zone history deleted successfully" });
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
struct GetZoneHistoriesParam {
    id: i32,
}

#[derive(Debug, Deserialize)]
struct DeleteZoneHistoryParam {
    _zone_id: i32,
    history_id: i32,
}
