use super::{
    auth,
    internal::{
        get_body, get_param, get_query, utils::json_response, Method, Request, Response, Router,
        StatusCode,
    },
};
use crate::{
    api::{
        dto::{CreateZoneRequest, GetRecordResponse, GetZoneResponse},
        service::{record::RecordService, zone::ZoneService},
    },
    database::DATABASE_POOL,
    serializer::Serializer,
};
use serde_json::json;

pub(crate) struct ZoneController;

impl ZoneController {
    pub(crate) async fn router() -> Router {
        let mut router = Router::new();

        router.register_endpoint_with_middleware(
            Method::GET,
            "/zones",
            ZoneController::get_zones,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::GET,
            "/zones/:id",
            ZoneController::get_zone,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::POST,
            "/zones",
            ZoneController::create_zone,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::PUT,
            "/zones/:id",
            ZoneController::update_zone,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::DELETE,
            "/zones/:id",
            ZoneController::delete_zone,
            auth::middleware::auth_middleware,
        );

        router
    }

    async fn get_zones(_request: Request) -> Response {
        let raw_zones = match ZoneService::get_zones(&DATABASE_POOL) {
            Ok(zones) => zones,
            Err(err) => {
                let json_body = json!({ "error": err });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let zones = raw_zones
            .iter()
            .map(|zone| GetZoneResponse::from_zone(zone))
            .collect::<Vec<GetZoneResponse>>();

        let json_body = json!({ "zones": zones });
        json_response(json_body, StatusCode::OK)
    }

    async fn get_zone(request: Request) -> Response {
        let zone_id = match get_param::<i32>(&request, "/zones/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };
        let records_query = get_query::<bool>(&request, "records");
        let render_query = get_query::<bool>(&request, "render");

        let raw_zone = match ZoneService::get_zone(&DATABASE_POOL, zone_id) {
            Ok(zone) => zone,
            Err(err) => {
                let json_body = json!({ "error": err });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_records = match records_query {
            Some(true) => match RecordService::get_records(&DATABASE_POOL, Some(zone_id)) {
                Ok(records) => records,
                Err(err) => {
                    let json_body = json!({ "error": err });
                    return json_response(json_body, StatusCode::BAD_REQUEST);
                }
            },
            _ => vec![],
        };
        let records = raw_records
            .iter()
            .map(|record| GetRecordResponse::from_record(record))
            .collect::<Vec<GetRecordResponse>>();

        if let Some(true) = render_query {
            let zone_str = Serializer::serialize_zone(&raw_zone, &raw_records);
            return json_response(json!({ "result": zone_str }), StatusCode::OK);
        }

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone, "records": records });
        json_response(json_body, StatusCode::OK)
    }

    async fn create_zone(request: Request) -> Response {
        let body = match get_body::<CreateZoneRequest>(request).await {
            Ok(b) => b,
            Err(err) => {
                eprintln!("Error parsing request body: {}", err);
                let json_body = json!({ "error": "Invalid request body" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_zone = match ZoneService::create_zone(&DATABASE_POOL, &body) {
            Ok(zone) => zone,
            Err(err) => {
                let json_body = json!({ "error": err });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone });

        json_response(json_body, StatusCode::OK)
    }

    async fn update_zone(request: Request) -> Response {
        let zone_id = match get_param::<i32>(&request, "/zones/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let body = match get_body::<CreateZoneRequest>(request).await {
            Ok(b) => b,
            Err(err) => {
                eprintln!("Error parsing request body: {}", err);
                let json_body = json!({ "error": "Invalid request body" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_zone = match ZoneService::update_zone(&DATABASE_POOL, zone_id, &body) {
            Ok(zone) => zone,
            Err(err) => {
                let json_body = json!({ "error": err });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone });

        json_response(json_body, StatusCode::OK)
    }

    async fn delete_zone(request: Request) -> Response {
        let zone_id = match get_param::<i32>(&request, "/zones/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        match ZoneService::delete_zone(&DATABASE_POOL, zone_id) {
            Ok(_) => {
                let json_body = json!({ "message": "Zone deleted successfully" });
                json_response(json_body, StatusCode::OK)
            }
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to delete zone: {}", err) });
                json_response(json_body, StatusCode::BAD_REQUEST)
            }
        }
    }
}
