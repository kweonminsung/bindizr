use crate::api::{
    controller::middleware::body_parser::JsonBody,
    dto::{CreateDnsServerRequest, GetDnsServerResponse, UpdateDnsServerRequest},
    service::dns_server::DnsServerService,
};
use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde::Deserialize;
use serde_json::json;

pub struct DnsServerController;

impl DnsServerController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/dns-servers", routing::get(Self::get_dns_servers))
            .route("/dns-servers/{id}", routing::get(Self::get_dns_server))
            .route("/dns-servers", routing::post(Self::create_dns_server))
            .route("/dns-servers/{id}", routing::put(Self::update_dns_server))
            .route(
                "/dns-servers/{id}",
                routing::delete(Self::delete_dns_server),
            )
    }

    async fn get_dns_servers() -> impl IntoResponse {
        match DnsServerService::get_dns_servers().await {
            Ok(dns_servers) => {
                let dns_servers = dns_servers
                    .iter()
                    .map(GetDnsServerResponse::from_dns_server)
                    .collect::<Vec<GetDnsServerResponse>>();
                let json_body = json!({ "dns_servers": dns_servers });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_dns_server(Path(params): Path<GetDnsServerParam>) -> impl IntoResponse {
        let dns_server_id = params.id;

        match DnsServerService::get_dns_server(dns_server_id).await {
            Ok(dns_server) => {
                let dns_server = GetDnsServerResponse::from_dns_server(&dns_server);
                let json_body = json!({ "dns_server": dns_server });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn create_dns_server(
        JsonBody(body): JsonBody<CreateDnsServerRequest>,
    ) -> impl IntoResponse {
        match DnsServerService::create_dns_server(&body).await {
            Ok(dns_server) => {
                let dns_server = GetDnsServerResponse::from_dns_server(&dns_server);
                let json_body = json!({ "dns_server": dns_server });
                (StatusCode::CREATED, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn update_dns_server(
        Path(params): Path<UpdateDnsServerParam>,
        JsonBody(body): JsonBody<UpdateDnsServerRequest>,
    ) -> impl IntoResponse {
        let dns_server_id = params.id;

        match DnsServerService::update_dns_server(dns_server_id, &body).await {
            Ok(dns_server) => {
                let dns_server = GetDnsServerResponse::from_dns_server(&dns_server);
                let json_body = json!({ "dns_server": dns_server });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_dns_server(Path(params): Path<DeleteDnsServerParam>) -> impl IntoResponse {
        let dns_server_id = params.id;

        match DnsServerService::delete_dns_server(dns_server_id).await {
            Ok(_) => {
                let json_body = json!({ "message": "DNS server deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}

#[derive(Deserialize)]
struct GetDnsServerParam {
    id: i32,
}

#[derive(Deserialize)]
struct UpdateDnsServerParam {
    id: i32,
}

#[derive(Deserialize)]
struct DeleteDnsServerParam {
    id: i32,
}
