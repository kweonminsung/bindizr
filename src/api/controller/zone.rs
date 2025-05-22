use super::internal::{Method, Request, Response, Router, StatusCode};
use crate::{
    api::{
        dto::{CreateZoneRequest, GetZoneResponse},
        service::ApiService,
        utils,
    },
    database::DATABASE_POOL,
    serializer::Serializer,
};
use serde_json::json;

pub struct ZoneController;

impl ZoneController {
    pub async fn router() -> Router {
        let mut router = Router::new();

        // register routes
        router.register_endpoint(Method::GET, "/zones", ZoneController::get_zones);
        router.register_endpoint(Method::GET, "/zones/:id", ZoneController::get_zone);
        router.register_endpoint(Method::POST, "/zones", ZoneController::create_zone);
        router.register_endpoint(Method::PUT, "/zones/:id", ZoneController::update_zone);
        router.register_endpoint(Method::DELETE, "/zones/:id", ZoneController::delete_zone);

        router
    }

    async fn get_zones(_request: Request) -> Response {
        let raw_zones = ApiService::get_zones(&DATABASE_POOL);

        let zones = raw_zones
            .iter()
            .map(|zone| GetZoneResponse::from_zone(zone))
            .collect::<Vec<GetZoneResponse>>();

        let json_body = json!({ "zones": zones });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn get_zone(request: Request) -> Response {
        let zone_id = match utils::get_param::<i32>(&request, "/zones/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };
        let records_query = utils::get_query::<bool>(&request, "records");
        let render_query = utils::get_query::<bool>(&request, "render");

        let raw_zone = match ApiService::get_zone(&DATABASE_POOL, zone_id) {
            Ok(zone) => zone,
            Err(_) => {
                let json_body = json!({ "error": "Zone not found" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let records = match records_query {
            Some(true) => ApiService::get_records(&DATABASE_POOL, Some(zone_id)),
            _ => vec![],
        };

        if let Some(true) = render_query {
            let zone_str = Serializer::serialize_zone(&raw_zone, &records);
            return utils::json_response(json!({ "result": zone_str }), StatusCode::OK);
        }

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone, "records": records });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn create_zone(request: Request) -> Response {
        let body = match utils::get_body::<CreateZoneRequest>(request).await {
            Ok(b) => b,
            Err(_) => {
                let json_body = json!({ "error": "Invalid request body" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_zone = match ApiService::create_zone(&DATABASE_POOL, &body) {
            Ok(zone) => zone,
            Err(err) => {
                // let json_body = json!({ "error": "Failed to create zone" });
                let json_body = json!({ "error": format!("Failed to create zone: {}", err) });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone });

        utils::json_response(json_body, StatusCode::OK)
    }

    async fn update_zone(request: Request) -> Response {
        let zone_id = match utils::get_param::<i32>(&request, "/zones/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let body = match utils::get_body::<CreateZoneRequest>(request).await {
            Ok(b) => b,
            Err(_) => {
                let json_body = json!({ "error": "Invalid request body" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_zone = match ApiService::update_zone(&DATABASE_POOL, zone_id, &body) {
            Ok(zone) => zone,
            Err(err) => {
                // let json_body = json!({ "error": "Failed to create zone" });
                let json_body = json!({ "error": format!("Failed to update zone: {}", err) });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone });

        utils::json_response(json_body, StatusCode::OK)
    }

    async fn delete_zone(request: Request) -> Response {
        let zone_id = match utils::get_param::<i32>(&request, "/zones/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        match ApiService::delete_zone(&DATABASE_POOL, zone_id) {
            Ok(_) => {
                let json_body = json!({ "message": "Zone deleted successfully" });
                utils::json_response(json_body, StatusCode::OK)
            }
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to delete zone: {}", err) });
                utils::json_response(json_body, StatusCode::BAD_REQUEST)
            }
        }
    }
}
