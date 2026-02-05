use crate::api::{
    controller::middleware::body_parser::JsonBody,
    dto::{CreateDnsKeyRequest, GetDnsKeyResponse, UpdateDnsKeyRequest},
    service::dns_key::DnsKeyService,
};
use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde_json::json;

pub struct DnsKeyController;

impl DnsKeyController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/dns/{dns_name}/key", routing::get(Self::get_dns_key))
            .route("/dns-keys", routing::post(Self::create_dns_key))
            .route("/dns/{dns_name}/key", routing::put(Self::update_dns_key))
            .route("/dns/{dns_name}/key", routing::delete(Self::delete_dns_key))
    }

    async fn get_dns_key(Path(dns_name): Path<String>) -> impl IntoResponse {
        match DnsKeyService::get_dns_keys(&dns_name).await {
            Ok(dns_keys) => {
                let response: Vec<GetDnsKeyResponse> = dns_keys
                    .iter()
                    .map(|(dns_key, key_name)| {
                        let mut resp = GetDnsKeyResponse::from_dns_key(dns_key);
                        resp.dns_name = Some(dns_name.clone());
                        resp.key_name = Some(key_name.clone());
                        resp
                    })
                    .collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn create_dns_key(JsonBody(request): JsonBody<CreateDnsKeyRequest>) -> impl IntoResponse {
        match DnsKeyService::create_dns_key(&request).await {
            Ok((dns_key, dns_name, key_name)) => {
                let mut response = GetDnsKeyResponse::from_dns_key(&dns_key);
                response.dns_name = Some(dns_name);
                response.key_name = Some(key_name);
                (StatusCode::CREATED, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn update_dns_key(
        Path(dns_name): Path<String>,
        JsonBody(request): JsonBody<UpdateDnsKeyRequest>,
    ) -> impl IntoResponse {
        match DnsKeyService::update_dns_key(&dns_name, &request).await {
            Ok((dns_key, dns_name, key_name)) => {
                let mut response = GetDnsKeyResponse::from_dns_key(&dns_key);
                response.dns_name = Some(dns_name);
                response.key_name = Some(key_name);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_dns_key(Path(dns_name): Path<String>) -> impl IntoResponse {
        match DnsKeyService::delete_dns_key(&dns_name).await {
            Ok(_) => {
                let json_body = json!({ "message": "DNS key deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}
