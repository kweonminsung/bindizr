use crate::api::{
    dto::{
        CreateZoneDnsConfigRequest, GetZoneDnsConfigResponse, UpdateZoneDnsConfigRequest,
    },
    service::zone_dns_config::ZoneDnsConfigService,
};
use axum::{
    extract::Path, http::StatusCode, response::IntoResponse, routing, Json, Router,
};
use serde_json::json;

pub struct ZoneDnsConfigController;

impl ZoneDnsConfigController {
    pub async fn routes() -> Router {
        Router::new()
            .route(
                "/zones/:zone_id/dns",
                routing::get(Self::get_zone_dns_configs),
            )
            .route(
                "/zones/:zone_id/dns",
                routing::post(Self::create_zone_dns_config),
            )
            .route(
                "/zones/:zone_id/dns/:dns_id",
                routing::put(Self::update_zone_dns_config),
            )
            .route(
                "/zones/:zone_id/dns/:dns_id",
                routing::delete(Self::delete_zone_dns_config),
            )
    }

    async fn get_zone_dns_configs(Path(zone_id): Path<i32>) -> impl IntoResponse {
        match ZoneDnsConfigService::get_zone_dns_configs(zone_id).await {
            Ok(configs) => {
                let response: Vec<GetZoneDnsConfigResponse> = configs
                    .iter()
                    .map(GetZoneDnsConfigResponse::from_zone_dns_config)
                    .collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn create_zone_dns_config(
        Path(zone_id): Path<i32>,
        Json(request): Json<CreateZoneDnsConfigRequest>,
    ) -> impl IntoResponse {
        match ZoneDnsConfigService::create_zone_dns_config(zone_id, &request).await {
            Ok(config) => {
                let response = GetZoneDnsConfigResponse::from_zone_dns_config(&config);
                (StatusCode::CREATED, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn update_zone_dns_config(
        Path((zone_id, dns_id)): Path<(i32, i32)>,
        Json(request): Json<UpdateZoneDnsConfigRequest>,
    ) -> impl IntoResponse {
        match ZoneDnsConfigService::update_zone_dns_config(zone_id, dns_id, &request).await {
            Ok(config) => {
                let response = GetZoneDnsConfigResponse::from_zone_dns_config(&config);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_zone_dns_config(Path((zone_id, dns_id)): Path<(i32, i32)>) -> impl IntoResponse {
        match ZoneDnsConfigService::delete_zone_dns_config(zone_id, dns_id).await {
            Ok(_) => {
                let json_body = json!({ "message": "Zone DNS configuration deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}
