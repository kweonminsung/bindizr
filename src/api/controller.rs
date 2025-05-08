use crate::api::service::ApiService;
use crate::api::utils;
use crate::parser::serialize_zone;

use http_body_util::Full;
use hyper::{body::Bytes, Method, Request, Response, StatusCode};
use serde_json::json;
use std::convert::Infallible;

pub struct ApiController {
    pub service: ApiService,
}

impl ApiController {
    pub fn new(service: ApiService) -> Self {
        Self { service }
    }

    pub fn route(
        &mut self,
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let routes = vec![
            Route {
                method: Method::GET,
                path: "/",
                handler: Box::new(ApiController::get_home),
            },
            // Route {
            //     method: Method::GET,
            //     path: "/test",
            //     handler: Box::new(ApiController::test),
            // },
            Route {
                method: Method::GET,
                path: "/zones",
                handler: Box::new(ApiController::get_zones),
            },
            Route {
                method: Method::GET,
                path: "/zones/:id",
                handler: Box::new(ApiController::get_zone),
            },
            Route {
                method: Method::GET,
                path: "/records",
                handler: Box::new(ApiController::get_records),
            },
            Route {
                method: Method::GET,
                path: "/records/:id",
                handler: Box::new(ApiController::get_record),
            },
        ];

        for route in routes {
            if request.method() == route.method
                && utils::match_path(request.uri().path(), route.path)
            {
                return (route.handler)(self, request);
            }
        }
        self.not_found()
    }

    fn not_found(&self) -> Result<Response<Full<Bytes>>, Infallible> {
        let json_body = json!({ "error": "Not Found" });
        utils::json_response(json_body, StatusCode::NOT_FOUND)
    }

    fn get_home(
        &self,
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        dbg!(request);

        utils::json_response(json!({ "msg": "hello world!" }), StatusCode::OK)
    }

    // fn test(
    //     &self,
    //     _request: Request<hyper::body::Incoming>,
    // ) -> Result<Response<Full<Bytes>>, Infallible> {
    //     let json_body = json!({ "result": self.service.get_table_names() });
    //     utils::json_response(json_body, StatusCode::OK)
    // }

    fn get_zones(
        &self,
        _request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let zones = self.service.get_zones();

        let json_body = json!({ "zones": zones });
        utils::json_response(json_body, StatusCode::OK)
    }

    fn get_zone(
        &self,
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

        let zone = self.service.get_zone(zone_id);

        let records = match records_query {
            Some(true) => self.service.get_records(Some(zone_id)),
            _ => vec![],
        };

        if let Some(true) = render_query {
            let zone_str = serialize_zone(&zone, &records);
            return utils::json_response(json!({ "result": zone_str }), StatusCode::OK);
        }
        let json_body = json!({ "zone": zone, "records": records });
        utils::json_response(json_body, StatusCode::OK)
    }

    fn get_records(
        &self,
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let zone_id = utils::get_query::<i32>(&request, "zone_id");

        let records = match zone_id {
            Some(id) => self.service.get_records(Some(id)),
            None => self.service.get_records(None),
        };

        let json_body = json!({ "records": records });
        utils::json_response(json_body, StatusCode::OK)
    }

    fn get_record(
        &self,
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let record_id = match utils::get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = self.service.get_record(record_id);

        let json_body = json!({ "record": record });
        utils::json_response(json_body, StatusCode::OK)
    }
}

pub struct Route {
    pub method: Method,
    pub path: &'static str,
    pub handler: Box<
        dyn Fn(
                &ApiController,
                Request<hyper::body::Incoming>,
            ) -> Result<Response<Full<Bytes>>, Infallible>
            + Send
            + Sync,
    >,
}
