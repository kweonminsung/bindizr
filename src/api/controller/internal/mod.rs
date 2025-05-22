use crate::api::utils;
use http_body_util::Full;
use hyper::body::Bytes;
use serde_json::json;
use std::convert::Infallible;

pub type Request = hyper::Request<hyper::body::Incoming>;
pub type Response = Result<hyper::Response<Full<Bytes>>, Infallible>;
pub type StatusCode = hyper::StatusCode;
pub type Method = hyper::Method;

pub struct Router {
    routes: Vec<Route>,
    not_found: fn() -> Response,
}

impl Router {
    pub fn new() -> Self {
        Router {
            routes: Vec::new(),
            not_found: Router::default_not_found,
        }
    }

    pub async fn route(&self, request: Request) -> Response {
        let method = request.method().clone();
        let path = request.uri().path();

        for route in &self.routes {
            if route.method == method && route.path == path {
                return (route.handler)(request).await;
            }
        }

        (self.not_found)()
    }

    fn default_not_found() -> Response {
        let json_body = json!({ "error": "Not Found" });
        utils::json_response(json_body, StatusCode::NOT_FOUND)
    }

    pub fn register_router(&mut self, mut router: Router) {
        self.routes.append(&mut router.routes);
    }

    pub fn register_endpoint<Fut>(
        &mut self,
        method: Method,
        path: &'static str,
        handler_fn: fn(Request) -> Fut,
    ) where
        Fut: std::future::Future<Output = Response> + Send + 'static,
    {
        self.routes.push(Route {
            method,
            path,
            handler: Box::new(move |req| Box::pin(handler_fn(req))),
        });
    }
}

pub struct Route {
    pub method: Method,
    pub path: &'static str,
    pub handler: Box<
        dyn Fn(Request) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
            + Send
            + Sync,
    >,
}
