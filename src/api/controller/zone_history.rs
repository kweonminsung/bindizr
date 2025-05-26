use super::{
    auth,
    internal::{get_param, utils::json_response, Method, Request, Response, Router, StatusCode},
};
use crate::{
    api::{dto::GetZoneHistoryResponse, service::zone_history::ZoneHistoryService},
    database::DATABASE_POOL,
};
use serde_json::json;

pub struct ZoneHistoryController;

impl ZoneHistoryController {
    pub async fn router() -> Router {
        let mut router = Router::new();

        router.register_endpoint(
            Method::GET,
            "/zones/:id/histories",
            ZoneHistoryController::get_zone_histories,
        );
        router.register_endpoint_with_middleware(
            Method::DELETE,
            "/zones/:zone_id/histories/:history_id",
            ZoneHistoryController::delete_zone_history,
            auth::middleware::auth_middleware,
        );

        router
    }

    async fn get_zone_histories(request: Request) -> Response {
        let zone_id = match get_param::<i32>(&request, "/zones/:id/histories", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_zone_histories =
            match ZoneHistoryService::get_zone_histories(&DATABASE_POOL, zone_id) {
                Ok(zone_histories) => zone_histories,
                Err(err) => {
                    let json_body = json!({ "error": err });
                    return json_response(json_body, StatusCode::BAD_REQUEST);
                }
            };

        let zone_histories = raw_zone_histories
            .iter()
            .map(|zone_history| GetZoneHistoryResponse::from_zone_history(zone_history))
            .collect::<Vec<GetZoneHistoryResponse>>();

        let json_body = json!({ "zone_histories": zone_histories });
        json_response(json_body, StatusCode::OK)
    }

    async fn delete_zone_history(request: Request) -> Response {
        let history_id = match get_param::<i32>(
            &request,
            "/zones/:zone_id/histories/:history_id",
            "history_id",
        ) {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing history_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        match ZoneHistoryService::delete_zone_history(&DATABASE_POOL, history_id) {
            Ok(_) => {
                let json_body = json!({ "message": "Zone history deleted successfully" });
                json_response(json_body, StatusCode::OK)
            }
            Err(err) => {
                let json_body = json!({ "error": err });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        }
    }
}
