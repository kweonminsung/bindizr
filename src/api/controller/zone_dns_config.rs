use crate::api::{
    dto::{CreateZoneDnsConfigRequest, GetZoneDnsConfigResponse, UpdateZoneDnsConfigRequest},
    service::zone_dns_config::ZoneDnsConfigService,
};
use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde_json::json;

pub struct ZoneDnsConfigController;

impl ZoneDnsConfigController {
    pub async fn routes() -> Router {
        Router::new()
            .route(
                "/zones/{zone_name}/dns",
                routing::get(Self::get_zone_dns_configs),
            )
            .route(
                "/zones/{zone_name}/dns",
                routing::post(Self::create_zone_dns_config),
            )
            .route(
                "/zones/{zone_name}/dns/{dns_name}",
                routing::put(Self::update_zone_dns_config),
            )
            .route(
                "/zones/{zone_name}/dns/{dns_name}",
                routing::delete(Self::delete_zone_dns_config),
            )
    }

    async fn get_zone_dns_configs(Path(zone_name): Path<String>) -> impl IntoResponse {
        match ZoneDnsConfigService::get_zone_dns_configs(&zone_name).await {
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
        Path(zone_name): Path<String>,
        Json(request): Json<CreateZoneDnsConfigRequest>,
    ) -> impl IntoResponse {
        match ZoneDnsConfigService::create_zone_dns_config(&zone_name, &request).await {
            Ok(config) => {
                let response = GetZoneDnsConfigResponse::from_zone_dns_config(&config);
                (StatusCode::CREATED, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn update_zone_dns_config(
        Path((zone_name, current_dns_name)): Path<(String, String)>,
        Json(request): Json<UpdateZoneDnsConfigRequest>,
    ) -> impl IntoResponse {
        match ZoneDnsConfigService::update_zone_dns_config(&zone_name, &current_dns_name, &request)
            .await
        {
            Ok(config) => {
                let response = GetZoneDnsConfigResponse::from_zone_dns_config(&config);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_zone_dns_config(
        Path((zone_name, dns_name)): Path<(String, String)>,
    ) -> impl IntoResponse {
        match ZoneDnsConfigService::delete_zone_dns_config(&zone_name, &dns_name).await {
            Ok(_) => {
                let json_body = json!({ "message": "Zone DNS configuration deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}
