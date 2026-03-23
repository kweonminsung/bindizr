use crate::api::{
    dto::{CreateDnsRequest, GetDnsKeyResponse, GetDnsResponse, UpdateDnsRequest},
    service::{dns::DnsService, dns_key::DnsKeyService},
};
use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde_json::json;

pub struct DnsController;

impl DnsController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/dns", routing::get(Self::get_dnss))
            .route("/dns", routing::post(Self::create_dns))
            .route("/dns/{name}", routing::get(Self::get_dns))
            .route("/dns/{name}", routing::put(Self::update_dns))
            .route("/dns/{name}", routing::delete(Self::delete_dns))
            .route("/dns/{name}/keys", routing::get(Self::get_dns_keys))
            .route("/dns/{name}/zones", routing::get(Self::get_dns_zones))
    }

    async fn get_dnss() -> impl IntoResponse {
        match DnsService::get_dnss().await {
            Ok(dnss) => {
                let response: Vec<GetDnsResponse> =
                    dnss.iter().map(GetDnsResponse::from_dns).collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_dns(Path(name): Path<String>) -> impl IntoResponse {
        match DnsService::get_dns(&name).await {
            Ok(dns) => {
                let response = GetDnsResponse::from_dns(&dns);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn create_dns(Json(request): Json<CreateDnsRequest>) -> impl IntoResponse {
        match DnsService::create_dns(&request).await {
            Ok(dns) => {
                let response = GetDnsResponse::from_dns(&dns);
                (StatusCode::CREATED, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn update_dns(
        Path(name): Path<String>,
        Json(request): Json<UpdateDnsRequest>,
    ) -> impl IntoResponse {
        match DnsService::update_dns(&name, &request).await {
            Ok(dns) => {
                let response = GetDnsResponse::from_dns(&dns);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_dns(Path(name): Path<String>) -> impl IntoResponse {
        match DnsService::delete_dns(&name).await {
            Ok(_) => {
                let json_body = json!({ "message": "DNS deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_dns_keys(Path(name): Path<String>) -> impl IntoResponse {
        match DnsKeyService::get_dns_keys(&name).await {
            Ok(keys) => {
                let response: Vec<GetDnsKeyResponse> = keys
                    .iter()
                    .map(|(dns_key, key_name)| {
                        let mut resp = GetDnsKeyResponse::from_dns_key(dns_key);
                        resp.dns_name = Some(name.clone());
                        resp.key_name = Some(key_name.clone());
                        resp
                    })
                    .collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_dns_zones(Path(name): Path<String>) -> impl IntoResponse {
        match DnsKeyService::get_dns_zones(&name).await {
            Ok(zone_ids) => {
                let json_body = json!({ "zone_ids": zone_ids });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}
