use crate::{
    api::{
        controller::middleware::body_parser::JsonBody,
        dto::{CreateZoneRequest, GetRecordResponse, GetZoneResponse},
        service::{record::RecordService, zone::ZoneService},
    },
    serializer::Serializer,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query},
    http::{Response, StatusCode, header},
    response::IntoResponse,
    routing,
};
use serde::Deserialize;
use serde_json::json;

pub struct ZoneController;

impl ZoneController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/zones", routing::get(Self::get_zones))
            .route("/zones/{id}", routing::get(Self::get_zone))
            .route(
                "/zones/{id}/rendered",
                routing::get(Self::get_zone_rendered),
            )
            .route("/zones", routing::post(Self::create_zone))
            .route("/zones/{id}", routing::put(Self::update_zone))
            .route("/zones/{id}", routing::delete(Self::delete_zone))
    }

    async fn get_zones() -> impl IntoResponse {
        let raw_zones = match ZoneService::get_zones().await {
            Ok(zones) => zones,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body));
            }
        };

        let zones = raw_zones
            .iter()
            .map(GetZoneResponse::from_zone)
            .collect::<Vec<GetZoneResponse>>();

        let json_body = json!({ "zones": zones });
        (StatusCode::OK, Json(json_body))
    }

    async fn get_zone(
        Path(params): Path<GetZoneParam>,
        Query(query): Query<GetZoneQuery>,
    ) -> impl IntoResponse {
        let zone_id = params.id;
        let records_query = query.records;

        let raw_zone = match ZoneService::get_zone(zone_id).await {
            Ok(zone) => zone,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body));
            }
        };

        let raw_records = match records_query {
            Some(true) => match RecordService::get_records(Some(zone_id)).await {
                Ok(records) => records,
                Err(err) => {
                    let json_body = json!({ "error": err });
                    return (StatusCode::BAD_REQUEST, Json(json_body));
                }
            },
            _ => vec![],
        };
        let records = raw_records
            .iter()
            .map(GetRecordResponse::from_record)
            .collect::<Vec<GetRecordResponse>>();

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone, "records": records });
        (StatusCode::OK, Json(json_body))
    }

    async fn get_zone_rendered(Path(params): Path<GetZoneParam>) -> impl IntoResponse {
        let zone_id = params.id;

        let raw_zone = match ZoneService::get_zone(zone_id).await {
            Ok(zone) => zone,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body)).into_response();
            }
        };

        let raw_records = match RecordService::get_records(Some(zone_id)).await {
            Ok(records) => records,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body)).into_response();
            }
        };

        let zone_str = Serializer::serialize_zone(&raw_zone, &raw_records);
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(zone_str))
            .unwrap()
            .into_response()
    }

    async fn create_zone(JsonBody(body): JsonBody<CreateZoneRequest>) -> impl IntoResponse {
        let raw_zone = match ZoneService::create_zone(&body).await {
            Ok(zone) => zone,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body));
            }
        };

        let zone = GetZoneResponse::from_zone(&raw_zone);

        let json_body = json!({ "zone": zone });
        (StatusCode::CREATED, Json(json_body))
    }

    async fn update_zone(
        Path(params): Path<UpdateZoneParam>,
        Json(body): Json<CreateZoneRequest>,
    ) -> impl IntoResponse {
        let zone_id = params.id;

        let raw_zone = match ZoneService::update_zone(zone_id, &body).await {
            Ok(zone) => zone,
            Err(err) => {
                let json_body = json!({ "error": err });
                return (StatusCode::BAD_REQUEST, Json(json_body));
            }
        };

        let zone = GetZoneResponse::from_zone(&raw_zone);

        let json_body = json!({ "zone": zone });
        (StatusCode::OK, Json(json_body))
    }

    async fn delete_zone(Path(params): Path<DeleteZoneParam>) -> impl IntoResponse {
        let zone_id = params.id;

        match ZoneService::delete_zone(zone_id).await {
            Ok(_) => {
                let json_body = json!({ "message": "Zone deleted successfully" });
                (StatusCode::OK, Json(json_body))
            }
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to delete zone: {}", err) });
                (StatusCode::BAD_REQUEST, Json(json_body))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct GetZoneParam {
    id: i32,
}

#[derive(Debug, Deserialize)]
struct GetZoneQuery {
    records: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateZoneParam {
    id: i32,
}

#[derive(Debug, Deserialize)]
struct DeleteZoneParam {
    id: i32,
}
