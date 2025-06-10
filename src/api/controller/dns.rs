use crate::api::service::dns::DnsService;
use axum::{http::StatusCode, response::IntoResponse, routing, Json, Router};
use serde_json::json;

pub struct DnsController;

impl DnsController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/dns/status", routing::get(Self::get_dns_status))
            .route("/dns/reload", routing::get(Self::reload_dns))
            .route("/dns/config", routing::post(Self::write_dns_config))
    }

    async fn get_dns_status() -> impl IntoResponse {
        let status = match DnsService::get_dns_status() {
            Ok(status) => status,
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to get DNS status: {}", err) });
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json_body));
            }
        };

        let json_body = json!({ "status": status  });
        (StatusCode::OK, Json(json_body))
    }

    async fn reload_dns() -> impl IntoResponse {
        let msg = match DnsService::reload_dns() {
            Ok(msg) => msg,
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to reload DNS: {}", err) });
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json_body));
            }
        };

        let json_body = json!({ "msg": msg  });
        (StatusCode::OK, Json(json_body))
    }

    async fn write_dns_config() -> impl IntoResponse {
        let msg = match DnsService::write_dns_config() {
            Ok(msg) => msg,
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to write DNS config: {}", err) });
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json_body));
            }
        };

        let json_body = json!({ "msg": msg  });
        (StatusCode::OK, Json(json_body))
    }
}
