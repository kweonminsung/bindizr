use crate::api::{
    controller::middleware::body_parser::JsonBody,
    dto::{CreateZoneRequest, GetRecordResponse, GetZoneResponse},
    service::{record::RecordService, zone::ZoneService},
};
use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
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
            .route("/zones/{name}", routing::get(Self::get_zone))
            .route("/zones", routing::post(Self::create_zone))
            .route("/zones/{name}", routing::put(Self::update_zone))
            .route("/zones/{name}", routing::delete(Self::delete_zone))
    }

    async fn get_zones() -> impl IntoResponse {
        match ZoneService::get_zones().await {
            Ok(zones) => {
                let zones = zones
                    .iter()
                    .map(GetZoneResponse::from_zone)
                    .collect::<Vec<GetZoneResponse>>();
                let json_body = json!({ "zones": zones });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_zone(
        Path(params): Path<GetZoneParam>,
        Query(query): Query<GetZoneQuery>,
    ) -> impl IntoResponse {
        let zone_name = params.name;
        let records_query = query.records;

        let raw_zone = match ZoneService::get_zone(&zone_name).await {
            Ok(zone) => zone,
            Err(err) => return err.into_response(),
        };

        let raw_records = match records_query {
            Some(true) => match RecordService::get_records(Some(raw_zone.name.clone())).await {
                Ok(records) => records,
                Err(err) => return err.into_response(),
            },
            _ => vec![],
        };
        let records = raw_records
            .iter()
            .map(GetRecordResponse::from_record)
            .collect::<Vec<GetRecordResponse>>();

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone, "records": records });
        (StatusCode::OK, Json(json_body)).into_response()
    }

    async fn create_zone(JsonBody(body): JsonBody<CreateZoneRequest>) -> impl IntoResponse {
        match ZoneService::create_zone(&body).await {
            Ok(zone) => {
                let zone = GetZoneResponse::from_zone(&zone);
                let json_body = json!({ "zone": zone });
                (StatusCode::CREATED, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn update_zone(
        Path(params): Path<UpdateZoneParam>,
        Json(body): Json<CreateZoneRequest>,
    ) -> impl IntoResponse {
        let zone_name = params.name;

        match ZoneService::update_zone(&zone_name, &body).await {
            Ok(zone) => {
                let zone = GetZoneResponse::from_zone(&zone);
                let json_body = json!({ "zone": zone });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_zone(Path(params): Path<DeleteZoneParam>) -> impl IntoResponse {
        let zone_name = params.name;

        match ZoneService::delete_zone(&zone_name).await {
            Ok(_) => {
                let json_body = json!({ "message": "Zone deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GetZoneParam {
    name: String,
}

#[derive(Debug, Deserialize)]
struct GetZoneQuery {
    records: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateZoneParam {
    name: String,
}

#[derive(Debug, Deserialize)]
struct DeleteZoneParam {
    name: String,
}
