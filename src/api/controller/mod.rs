pub(crate) mod auth;
mod dns;
mod internal;
mod record;
mod record_history;
mod zone;
mod zone_history;

use internal::{utils, Method, Request, Response, Router, StatusCode};
use serde_json::json;

pub(crate) struct ApiController;

impl ApiController {
    pub(crate) async fn serve(request: Request) -> Response {
        let mut router = Router::new();

        // Register routes
        router.register_router(record::RecordController::router().await);
        router.register_router(zone::ZoneController::router().await);
        router.register_router(zone_history::ZoneHistoryController::router().await);
        router.register_router(record_history::RecordHistoryController::router().await);
        router.register_router(dns::DnsController::router().await);

        // router.register_endpoint(Method::GET, "/test", test);
        router.register_endpoint(Method::GET, "/", ApiController::get_home);

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
}
