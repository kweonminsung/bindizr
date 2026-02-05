use crate::api::{
    dto::{CreateDnsKeyRequest, GetDnsKeyResponse, UpdateDnsKeyRequest},
    service::dns_key::DnsKeyService,
};
use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde_json::json;

pub struct DnsKeyController;

impl DnsKeyController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/keys", routing::get(Self::get_dns_keys))
            .route("/keys", routing::post(Self::create_dns_key))
            .route("/keys/{key_name}", routing::get(Self::get_dns_key))
            .route("/keys/{key_name}", routing::put(Self::update_dns_key))
            .route("/keys/{key_name}", routing::delete(Self::delete_dns_key))
    }

    async fn get_dns_keys() -> impl IntoResponse {
        match DnsKeyService::get_dns_keys().await {
            Ok(dns_keys) => {
                let response: Vec<GetDnsKeyResponse> = dns_keys
                    .iter()
                    .map(GetDnsKeyResponse::from_dns_key)
                    .collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_dns_key(Path(key_name): Path<String>) -> impl IntoResponse {
        match DnsKeyService::get_dns_key(&key_name).await {
            Ok(dns_key) => {
                let response = GetDnsKeyResponse::from_dns_key(&dns_key);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn create_dns_key(Json(request): Json<CreateDnsKeyRequest>) -> impl IntoResponse {
        match DnsKeyService::create_dns_key(&request).await {
            Ok(dns_key) => {
                let response = GetDnsKeyResponse::from_dns_key(&dns_key);
                (StatusCode::CREATED, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn update_dns_key(
        Path(key_name): Path<String>,
        Json(request): Json<UpdateDnsKeyRequest>,
    ) -> impl IntoResponse {
        match DnsKeyService::update_dns_key(&key_name, &request).await {
            Ok(dns_key) => {
                let response = GetDnsKeyResponse::from_dns_key(&dns_key);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_dns_key(Path(key_name): Path<String>) -> impl IntoResponse {
        match DnsKeyService::delete_dns_key(&key_name).await {
            Ok(_) => {
                let json_body = json!({ "message": "DNS key deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}
