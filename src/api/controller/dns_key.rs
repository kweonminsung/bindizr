use crate::api::{
    dto::{CreateDnsKeyRequest, GetDnsKeyResponse, UpdateDnsKeyRequest},
    service::dns_key::DnsKeyService,
};
use axum::{
    extract::Path, http::StatusCode, response::IntoResponse, routing, Json, Router,
};
use serde_json::json;

pub struct DnsKeyController;

impl DnsKeyController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/keys", routing::get(Self::get_dns_keys))
            .route("/keys", routing::post(Self::create_dns_key))
            .route("/keys/{id}", routing::get(Self::get_dns_key))
            .route("/keys/{id}", routing::put(Self::update_dns_key))
            .route("/keys/{id}", routing::delete(Self::delete_dns_key))
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

    async fn get_dns_key(Path(id): Path<i32>) -> impl IntoResponse {
        match DnsKeyService::get_dns_key(id).await {
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
        Path(id): Path<i32>,
        Json(request): Json<UpdateDnsKeyRequest>,
    ) -> impl IntoResponse {
        match DnsKeyService::update_dns_key(id, &request).await {
            Ok(dns_key) => {
                let response = GetDnsKeyResponse::from_dns_key(&dns_key);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_dns_key(Path(id): Path<i32>) -> impl IntoResponse {
        match DnsKeyService::delete_dns_key(id).await {
            Ok(_) => {
                let json_body = json!({ "message": "DNS key deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}
