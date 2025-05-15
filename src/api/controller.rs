use crate::api::utils;
use crate::serializer::Serializer;

use crate::api::service::ApiService;
use http_body_util::Full;
use hyper::{body::Bytes, Method, Request, Response, StatusCode};
use serde_json::json;
use std::convert::Infallible;

use super::service::DATABASE_POOL;

pub struct ApiController;

impl ApiController {
    pub fn route(
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let routes = vec![
            Route {
                method: Method::GET,
                path: "/",
                handler: ApiController::get_home,
            },
            // Route {
            //     method: Method::GET,
            //     path: "/test",
            //     handler: ApiController::test,
            // },
            Route {
                method: Method::GET,
                path: "/zones",
                handler: ApiController::get_zones,
            },
            Route {
                method: Method::GET,
                path: "/zones/:id",
                handler: ApiController::get_zone,
            },
            Route {
                method: Method::GET,
                path: "/records",
                handler: ApiController::get_records,
            },
            Route {
                method: Method::GET,
                path: "/records/:id",
                handler: ApiController::get_record,
            },
        ];

        for route in routes {
            if request.method() == route.method
                && utils::match_path(request.uri().path(), route.path)
            {
                return (route.handler)(request);
            }
        }
        ApiController::not_found()
    }

    fn not_found() -> Result<Response<Full<Bytes>>, Infallible> {
        let json_body = json!({ "error": "Not Found" });
        utils::json_response(json_body, StatusCode::NOT_FOUND)
    }

    fn get_home(
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        dbg!(request);

        utils::json_response(json!({ "msg": "hello world!" }), StatusCode::OK)
    }

    // fn test(
    //     &self,
    //     _request: Request<hyper::body::Incoming>,
    // ) -> Result<Response<Full<Bytes>>, Infallible> {
    //     let json_body = json!({ "result": API_SERVICE.get_table_names() });
    //     utils::json_response(json_body, StatusCode::OK)
    // }

    fn get_zones(
        _request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let zones = ApiService::get_zones(&DATABASE_POOL);

        let json_body = json!({ "zones": zones });
        utils::json_response(json_body, StatusCode::OK)
    }

    fn get_zone(
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
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

    fn get_records(
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let zone_id = utils::get_query::<i32>(&request, "zone_id");

        let records = match zone_id {
            Some(id) => ApiService::get_records(&DATABASE_POOL, Some(id)),
            None => ApiService::get_records(&DATABASE_POOL, None),
        };

        let json_body = json!({ "records": records });
        utils::json_response(json_body, StatusCode::OK)
    }

    fn get_record(
        request: Request<hyper::body::Incoming>,
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
}

pub struct Route {
    pub method: Method,
    pub path: &'static str,
    pub handler: fn(Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible>,
}
