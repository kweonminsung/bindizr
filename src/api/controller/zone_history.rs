use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde::Deserialize;
use serde_json::json;

use crate::api::{dto::GetZoneHistoryResponse, service::zone_history::ZoneHistoryService};

pub struct ZoneHistoryController;

impl ZoneHistoryController {
    pub async fn routes() -> Router {
        Router::new().route(
            "/zones/{name}/histories",
            routing::get(Self::get_zone_histories),
        )
    }

    async fn get_zone_histories(Path(params): Path<GetZoneHistoriesParam>) -> impl IntoResponse {
        let zone_name = params.name;

        let raw_zone_histories = match ZoneHistoryService::get_zone_histories(&zone_name).await {
            Ok(zone_histories) => zone_histories,
            Err(err) => return err.into_response(),
        };

        let zone_histories = raw_zone_histories
            .iter()
            .map(GetZoneHistoryResponse::from_zone_history)
            .collect::<Vec<GetZoneHistoryResponse>>();

        let json_body = json!({ "zone_histories": zone_histories });
        (StatusCode::OK, Json(json_body)).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct GetZoneHistoriesParam {
    name: String,
}
