use super::dto::{CreateRecordRequest, CreateZoneRequest, GetZoneResponse};
use crate::api::dto::GetRecordResponse;
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
            Method::POST,
            "/zones",
            ApiController::create_zone,
        );
        Self::push_route(
            &mut routes,
            Method::PUT,
            "/zones/:id",
            ApiController::update_zone,
        );
        Self::push_route(
            &mut routes,
            Method::DELETE,
            "/zones/:id",
            ApiController::delete_zone,
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
            Method::PUT,
            "/records/:id",
            ApiController::update_record,
        );
        Self::push_route(
            &mut routes,
            Method::DELETE,
            "/records/:id",
            ApiController::delete_record,
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
        let raw_zones = ApiService::get_zones(&DATABASE_POOL);

        let zones = raw_zones
            .iter()
            .map(|zone| GetZoneResponse::from_zone(zone))
            .collect::<Vec<GetZoneResponse>>();

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

        let raw_zone = match ApiService::get_zone(&DATABASE_POOL, zone_id) {
            Ok(zone) => zone,
            Err(_) => {
                let json_body = json!({ "error": "Zone not found" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let records = match records_query {
            Some(true) => ApiService::get_records(&DATABASE_POOL, Some(zone_id)),
            _ => vec![],
        };

        if let Some(true) = render_query {
            let zone_str = Serializer::serialize_zone(&raw_zone, &records);
            return utils::json_response(json!({ "result": zone_str }), StatusCode::OK);
        }

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone, "records": records });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn create_zone(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = match utils::get_body::<CreateZoneRequest>(request).await {
            Ok(b) => b,
            Err(_) => {
                let json_body = json!({ "error": "Invalid request body" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_zone = match ApiService::create_zone(&DATABASE_POOL, &body) {
            Ok(zone) => zone,
            Err(err) => {
                // let json_body = json!({ "error": "Failed to create zone" });
                let json_body = json!({ "error": format!("Failed to create zone: {}", err) });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone });

        utils::json_response(json_body, StatusCode::OK)
    }

    async fn update_zone(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let zone_id = match utils::get_param::<i32>(&request, "/zones/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let body = match utils::get_body::<CreateZoneRequest>(request).await {
            Ok(b) => b,
            Err(_) => {
                let json_body = json!({ "error": "Invalid request body" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_zone = match ApiService::update_zone(&DATABASE_POOL, zone_id, &body) {
            Ok(zone) => zone,
            Err(err) => {
                // let json_body = json!({ "error": "Failed to create zone" });
                let json_body = json!({ "error": format!("Failed to update zone: {}", err) });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let zone = GetZoneResponse::from_zone(&raw_zone);
        let json_body = json!({ "zone": zone });

        utils::json_response(json_body, StatusCode::OK)
    }

    async fn delete_zone(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let zone_id = match utils::get_param::<i32>(&request, "/zones/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing zone_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        match ApiService::delete_zone(&DATABASE_POOL, zone_id) {
            Ok(_) => {
                let json_body = json!({ "message": "Zone deleted successfully" });
                utils::json_response(json_body, StatusCode::OK)
            }
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to delete zone: {}", err) });
                utils::json_response(json_body, StatusCode::BAD_REQUEST)
            }
        }
    }

    async fn get_records(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let zone_id = utils::get_query::<i32>(&request, "zone_id");

        let raw_records = ApiService::get_records(&DATABASE_POOL, zone_id);

        let records = raw_records
            .iter()
            .map(|record| GetRecordResponse::from_record(record))
            .collect::<Vec<GetRecordResponse>>();

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

        let raw_record = match ApiService::get_record(&DATABASE_POOL, record_id) {
            Ok(record) => record,
            Err(_) => {
                let json_body = json!({ "error": "Record not found" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);

        let json_body = json!({ "record": record });
        utils::json_response(json_body, StatusCode::OK)
    }

    async fn create_record(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = match utils::get_body::<CreateRecordRequest>(request).await {
            Ok(b) => b,
            Err(_) => {
                let json_body = json!({ "error": "Invalid request body" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record = match ApiService::create_record(&DATABASE_POOL, &body) {
            Ok(record) => record,
            Err(_) => {
                let json_body = json!({ "error": "Failed to create record" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);
        let json_body = json!({ "record": record });

        utils::json_response(json_body, StatusCode::OK)
    }

    async fn update_record(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let record_id = match utils::get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let body = match utils::get_body::<CreateRecordRequest>(request).await {
            Ok(b) => b,
            Err(_) => {
                let json_body = json!({ "error": "Invalid request body" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let raw_record = match ApiService::update_record(&DATABASE_POOL, record_id, &body) {
            Ok(record) => record,
            Err(_) => {
                let json_body = json!({ "error": "Failed to update record" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        let record = GetRecordResponse::from_record(&raw_record);
        let json_body = json!({ "record": record });

        utils::json_response(json_body, StatusCode::OK)
    }

    async fn delete_record(
        request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let record_id = match utils::get_param::<i32>(&request, "/records/:id", "id") {
            Some(id) => id,
            None => {
                let json_body = json!({ "error": "Invalid or missing record_id" });
                return utils::json_response(json_body, StatusCode::BAD_REQUEST);
            }
        };

        match ApiService::delete_record(&DATABASE_POOL, record_id) {
            Ok(_) => {
                let json_body = json!({ "message": "Record deleted successfully" });
                utils::json_response(json_body, StatusCode::OK)
            }
            Err(err) => {
                let json_body = json!({ "error": format!("Failed to delete record: {}", err) });
                utils::json_response(json_body, StatusCode::BAD_REQUEST)
            }
        }
    }

    async fn get_dns_status(
        _request: Request<RequestBody>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
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
