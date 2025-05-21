use super::dto::CreateRecordRequest;
use crate::api::service::ApiService;
use crate::serializer::Serializer;
use crate::{api::utils, database::DATABASE_POOL};
use http_body_util::Full;
use hyper::{body::Bytes, Method, Request, Response, StatusCode};
use serde_json::json;
use std::convert::Infallible;

type RequestBody = hyper::body::Incoming;

pub struct ApiController;

impl ApiController {
    pub async fn route(request: Request<RequestBody>) -> Result<Response<Full<Bytes>>, Infallible> {
        let mut routes = Vec::new();
        Self::push_route(&mut routes, Method::GET, "/", ApiController::get_home);
        // Self::push_route(&mut routes, Method::GET, "/test", test);
        Self::push_route(&mut routes, Method::GET, "/zones", ApiController::get_zones);
        Self::push_route(
            &mut routes,
            Method::GET,
            "/zones/:id",
            ApiController::get_zone,
        );
        Self::push_route(
            &mut routes,
            Method::GET,
            "/records",
            ApiController::get_records,
        );
        Self::push_route(
            &mut routes,
            Method::POST,
            "/records",
            ApiController::create_record,
        );
        Self::push_route(
            &mut routes,
            Method::GET,
            "/records/:id",
            ApiController::get_record,
        );
        Self::push_route(
            &mut routes,
            Method::GET,
            "/dns/status",
            ApiController::get_dns_status,
        );

        for route in routes {
            if request.method() == route.method
                && utils::match_path(request.uri().path(), route.path)
            {
                return (route.handler)(request).await;
            }
        }
        ApiController::not_found().await
    }

    fn push_route<Fut>(
        routes: &mut Vec<Route>,
        method: Method,
        path: &'static str,
        handler_fn: fn(Request<RequestBody>) -> Fut,
    ) where
        Fut: std::future::Future<Output = Result<Response<Full<Bytes>>, Infallible>>
            + Send
            + 'static,
    {
        routes.push(Route {
            method,
            path,
            handler: Box::new(move |req| Box::pin(handler_fn(req))),
        });
    }

    async fn not_found() -> Result<Response<Full<Bytes>>, Infallible> {
        let json_body = json!({ "error": "Not Found" });
        utils::json_response(json_body, StatusCode::NOT_FOUND)
    }

    async fn get_home(request: Request<RequestBody>) -> Result<Response<Full<Bytes>>, Infallible> {
        dbg!(request);

        utils::json_response(json!({ "msg": "hello world!" }), StatusCode::OK)
    }

    // fn test(
    //     &self,
    //     _request: Request<RequestBody>,
    // ) -> Result<Response<Full<Bytes>>, Infallible> {
    //     let json_body = json!({ "result": API_SERVICE.get_table_names() });
    //     utils::json_response(json_body, StatusCode::OK)
    // }

    async fn get_zones(
        _request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let zones = ApiService::get_zones(&DATABASE_POOL);

        let json_body = json!({ "zones": zones });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn get_zone(request: Request<RequestBody>) -> Result<Response<Full<Bytes>>, Infallible> {
        let zone_id = match utils::get_param::<i32>(&request, "/zones/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };
        let records_query = utils::get_query::<bool>(&request, "records");
        let render_query = utils::get_query::<bool>(&request, "render");

        let zone = ApiService::get_zone(&DATABASE_POOL, zone_id);

        let records = match records_query {
            Some(true) => ApiService::get_records(&DATABASE_POOL, Some(zone_id)),
            _ => vec![],
        };

        if let Some(true) = render_query {
            let zone_str = Serializer::serialize_zone(&zone, &records);
            return utils::json_response(json!({ "result": zone_str }), StatusCode::OK);
        }
        let json_body = json!({ "zone": zone, "records": records });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn get_records(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let zone_id = utils::get_query::<i32>(&request, "zone_id");

        let records = match zone_id {
            Some(id) => ApiService::get_records(&DATABASE_POOL, Some(id)),
            None => ApiService::get_records(&DATABASE_POOL, None),
        };

        let json_body = json!({ "records": records });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn get_record(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let record_id = match utils::get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = ApiService::get_record(&DATABASE_POOL, record_id);

        let json_body = json!({ "record": record });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn create_record(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = utils::get_body::<CreateRecordRequest>(request)
            .await
            .unwrap();

        let record = ApiService::create_record(&DATABASE_POOL, &body);

        let json_body = json!({ "body": body });

        utils::json_response(json_body, StatusCode::OK)
    }

    async fn get_dns_status(
        _request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let status = ApiService::get_dns_status();

        let json_body = json!({ "status": status  });
        utils::json_response(json_body, StatusCode::OK)
    }
}

pub struct Route {
    pub method: Method,
    pub path: &'static str,
    pub handler: Box<
        dyn Fn(
                Request<RequestBody>,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<Response<Full<Bytes>>, Infallible>>
                        + Send,
                >,
            > + Send
            + Sync,
    >,
}
