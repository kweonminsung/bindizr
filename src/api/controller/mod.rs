mod internal;
mod record;
mod zone;

use super::service::ApiService;
use crate::api::utils;
use hyper::Method;
use internal::{Request, Response, Router, StatusCode};
use serde_json::json;

pub struct ApiController;

impl ApiController {
    pub async fn serve(request: Request) -> Response {
        let mut router = Router::new();

        // register routes
        router.register_router(record::RecordController::router().await);
        router.register_router(zone::ZoneController::router().await);

        // router.register_endpoint(Method::GET, "/test", test);
        router.register_endpoint(Method::GET, "/", ApiController::get_home);
        router.register_endpoint(Method::GET, "/dns/status", ApiController::get_dns_status);

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
        let status = match ApiService::get_dns_status() {
            Ok(status) => status,
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to get DNS status: {}", err) });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let json_body = json!({ "status": status  });
        utils::json_response(json_body, StatusCode::OK)
    }
}
