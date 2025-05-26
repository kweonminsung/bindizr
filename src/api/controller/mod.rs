pub mod auth;
mod internal;
mod record;
mod record_history;
mod zone;
mod zone_history;

use super::service::test::TestService;
use internal::{utils, Method, Request, Response, Router, StatusCode};
use serde_json::json;

pub struct ApiController;

impl ApiController {
    pub async fn serve(request: Request) -> Response {
        let mut router = Router::new();

        // Register routes
        router.register_router(record::RecordController::router().await);
        router.register_router(zone::ZoneController::router().await);
        router.register_router(zone_history::ZoneHistoryController::router().await);
        router.register_router(record_history::RecordHistoryController::router().await);

        // router.register_endpoint(Method::GET, "/test", test);
        router.register_endpoint(Method::GET, "/", ApiController::get_home);
        router.register_endpoint_with_middleware(
            Method::GET,
            "/dns/status",
            ApiController::get_dns_status,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::GET,
            "/dns/reload",
            ApiController::reload_dns,
            auth::middleware::auth_middleware,
        );
        router.register_endpoint_with_middleware(
            Method::POST,
            "/dns/config",
            ApiController::write_dns_config,
            auth::middleware::auth_middleware,
        );

        router.route(request).await
    }

    async fn get_home(request: Request) -> Response {
        dbg!(request);

        utils::json_response(json!({ "msg": "hello world!" }), StatusCode::OK)
    }

    // fn test(&self, _request: Request) -> Response {
    //     let json_body = json!({ "result": ApiService.get_table_names() });
    //     utils::json_response(json_body, StatusCode::OK)
    // }

    async fn get_dns_status(_request: Request) -> Response {
        let status = match TestService::get_dns_status() {
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
        let msg = match TestService::reload_dns() {
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
        let msg = match TestService::write_dns_config() {
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
