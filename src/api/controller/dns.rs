use crate::api::{
    controller::{
        auth,
        internal::{utils, Method, Request, Response, Router, StatusCode},
    },
    service::dns::DnsService,
};
use serde_json::json;

pub struct DnsController;

impl DnsController {
    pub async fn router() -> Router {
        let mut router = Router::new();

        router.register_endpoint_with_middleware(
            Method::GET,
            "/dns/status",
            DnsController::get_dns_status,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::GET,
            "/dns/reload",
            DnsController::reload_dns,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::POST,
            "/dns/config",
            DnsController::write_dns_config,
            auth::middleware::auth_middleware,
        );

        router
    }

    async fn get_dns_status(_request: Request) -> Response {
        let status = match DnsService::get_dns_status() {
            Ok(status) => status,
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to get DNS status: {}", err) });
                return utils::json_response(json_body, StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        let json_body = json!({ "status": status  });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn reload_dns(_request: Request) -> Response {
        let msg = match DnsService::reload_dns() {
            Ok(msg) => msg,
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to reload DNS: {}", err) });
                return utils::json_response(json_body, StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        let json_body = json!({ "msg": msg  });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn write_dns_config(_request: Request) -> Response {
        let msg = match DnsService::write_dns_config() {
            Ok(msg) => msg,
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to write DNS config: {}", err) });
                return utils::json_response(json_body, StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        let json_body = json!({ "msg": msg  });
        utils::json_response(json_body, StatusCode::OK)
    }
}
