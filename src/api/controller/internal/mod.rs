pub mod utils;

use http_body_util::{BodyExt, Full};
use hyper::body::{Buf, Bytes};
use serde::de::DeserializeOwned;
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
        for route in &self.routes {
            if request.method() == route.method
                && Router::match_path(request.uri().path(), route.path)
            {
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

    fn match_path(request_path: &str, route_path: &str) -> bool {
        let req_parts: Vec<_> = request_path.trim_matches('/').split('/').collect();
        let route_parts: Vec<_> = route_path.trim_matches('/').split('/').collect();

        if req_parts.len() != route_parts.len() {
            return false;
        }

        for (r, p) in route_parts.iter().zip(req_parts.iter()) {
            if !r.starts_with(':') && r != p {
                return false;
            }
        }

        true
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

pub fn get_param<T>(
    request: &hyper::Request<hyper::body::Incoming>,
    route_path: &str,
    key: &str,
) -> Option<T>
where
    T: std::str::FromStr,
{
    let request_path = request.uri().path();

    let req_parts: Vec<&str> = request_path.trim_matches('/').split('/').collect();
    let route_parts: Vec<&str> = route_path.trim_matches('/').split('/').collect();

    // return None if the length of the request path and the router path are different
    if req_parts.len() != route_parts.len() {
        return None;
    }

    for (req_part, route_part) in req_parts.iter().zip(route_parts.iter()) {
        if route_part.starts_with(':') {
            let param_name = &route_part[1..]; // extract the part after ':'
            if param_name == key {
                return req_part.parse::<T>().ok();
            }
        }
    }

    None
}

pub fn get_query<T>(request: &Request, key: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    let query = request.uri().query()?;
    let params: Vec<&str> = query.split('&').collect();
    for param in params {
        let pair: Vec<&str> = param.split('=').collect();
        if pair.len() == 2 && pair[0] == key {
            return pair[1].parse::<T>().ok();
        }
    }
    None
}

pub async fn get_body<T>(request: Request) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let whole_body = request
        .collect()
        .await
        .map_err(|e| format!("Failed to collect body: {}", e))?
        .aggregate();

    let data = serde_json::from_reader(whole_body.reader())
        .map_err(|e| format!("Failed to parse JSON: {}", e));

    data
}
