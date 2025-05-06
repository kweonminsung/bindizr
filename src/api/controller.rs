use crate::api::service::ApiService;
use crate::api::utils;
use http_body_util::Full;
use hyper::{body::Bytes, Request, Response, StatusCode};
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
        match (request.method(), request.uri().path()) {
            // (&hyper::Method::GET, "/") => self.get_home(request).await,
            (&hyper::Method::GET, "/test") => self.test(),
            _ => self.not_found(),
        }
    }

    // fn get_home(
    //     &self,
    //     request: Request<hyper::body::Incoming>,
    // ) -> Result<Response<Full<Bytes>>, Infallible> {
    //     dbg!(request);

    //     utils::json_response(json!({ "msg": "hello world!" }), StatusCode::OK).await
    // }

    fn not_found(&self) -> Result<Response<Full<Bytes>>, Infallible> {
        utils::json_response(json!({ "msg": "404 not found" }), StatusCode::NOT_FOUND)
    }

    fn test(&self) -> Result<Response<Full<Bytes>>, Infallible> {
        let json_body = json!({ "result": self.service.get_table_names() });

        utils::json_response(json_body, StatusCode::OK)
    }
}
