use crate::api::{
    dto::{
        CreateDnsInstanceRequest, GetDnsInstanceResponse, GetDnsKeyResponse,
        UpdateDnsInstanceRequest,
    },
    service::dns_instance::DnsInstanceService,
};
use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde_json::json;

pub struct DnsInstanceController;

impl DnsInstanceController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/dns", routing::get(Self::get_dns_instances))
            .route("/dns", routing::post(Self::create_dns_instance))
            .route("/dns/{id}", routing::get(Self::get_dns_instance))
            .route("/dns/{id}", routing::put(Self::update_dns_instance))
            .route("/dns/{id}", routing::delete(Self::delete_dns_instance))
            .route("/dns/{id}/keys", routing::get(Self::get_dns_instance_keys))
            .route(
                "/dns/{id}/zones",
                routing::get(Self::get_dns_instance_zones),
            )
    }

    async fn get_dns_instances() -> impl IntoResponse {
        match DnsInstanceService::get_dns_instances().await {
            Ok(dns_instances) => {
                let response: Vec<GetDnsInstanceResponse> = dns_instances
                    .iter()
                    .map(GetDnsInstanceResponse::from_dns_instance)
                    .collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_dns_instance(Path(id): Path<i32>) -> impl IntoResponse {
        match DnsInstanceService::get_dns_instance(id).await {
            Ok(dns_instance) => {
                let response = GetDnsInstanceResponse::from_dns_instance(&dns_instance);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn create_dns_instance(
        Json(request): Json<CreateDnsInstanceRequest>,
    ) -> impl IntoResponse {
        match DnsInstanceService::create_dns_instance(&request).await {
            Ok(dns_instance) => {
                let response = GetDnsInstanceResponse::from_dns_instance(&dns_instance);
                (StatusCode::CREATED, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn update_dns_instance(
        Path(id): Path<i32>,
        Json(request): Json<UpdateDnsInstanceRequest>,
    ) -> impl IntoResponse {
        match DnsInstanceService::update_dns_instance(id, &request).await {
            Ok(dns_instance) => {
                let response = GetDnsInstanceResponse::from_dns_instance(&dns_instance);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_dns_instance(Path(id): Path<i32>) -> impl IntoResponse {
        match DnsInstanceService::delete_dns_instance(id).await {
            Ok(_) => {
                let json_body = json!({ "message": "DNS instance deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_dns_instance_keys(Path(id): Path<i32>) -> impl IntoResponse {
        match DnsInstanceService::get_dns_instance_keys(id).await {
            Ok(keys) => {
                let response: Vec<GetDnsKeyResponse> =
                    keys.iter().map(GetDnsKeyResponse::from_dns_key).collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_dns_instance_zones(Path(id): Path<i32>) -> impl IntoResponse {
        match DnsInstanceService::get_dns_instance_zones(id).await {
            Ok(zone_ids) => {
                let json_body = json!({ "zone_ids": zone_ids });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}
