pub mod utils;

use http_body_util::{BodyExt, Full};
use hyper::body::{Buf, Bytes};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;

pub type Request = hyper::Request<hyper::body::Incoming>;
pub type Response = Result<hyper::Response<Full<Bytes>>, Infallible>;
pub type StatusCode = hyper::StatusCode;
pub type Method = hyper::Method;

#[derive(Clone, PartialEq, Eq, Hash)]
struct RouteKey {
    method: Method,
    path_pattern: &'static str,
}

pub struct Router {
    routes: HashMap<RouteKey, Route>,
    not_found: fn() -> Response,
}

impl Router {
    pub fn new() -> Self {
        Router {
            routes: HashMap::new(),
            not_found: Router::default_not_found,
        }
    }

    pub async fn route(&self, request: Request) -> Response {
        let path = request.uri().path();
        let method = request.method().clone();

        for (key, route) in &self.routes {
            if &method == &key.method && Router::match_path(path, key.path_pattern) {
                return (route.handler)(request).await;
            }
        }

        (self.not_found)()
    }

    fn default_not_found() -> Response {
        let json_body = json!({ "error": "Not Found" });
        utils::json_response(json_body, StatusCode::NOT_FOUND)
    }

    pub fn register_router(&mut self, router: Router) {
        for (key, route) in router.routes {
            self.routes.insert(key, route);
        }
    }

    pub fn register_endpoint<Fut>(
        &mut self,
        method: Method,
        path: &'static str,
        handler_fn: fn(Request) -> Fut,
    ) where
        Fut: std::future::Future<Output = Response> + Send + 'static,
    {
        let key = RouteKey {
            method,
            path_pattern: path,
        };

        self.routes.insert(
            key,
            Route {
                handler: Box::new(move |req| Box::pin(handler_fn(req))),
            },
        );
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
    pub handler: Box<
        dyn Fn(Request) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
            + Send
            + Sync,
    >,
}

pub fn get_param<T>(request: &Request, route_path: &str, key: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    let request_path = request.uri().path();
    let req_parts: Vec<&str> = request_path.trim_matches('/').split('/').collect();
    let route_parts: Vec<&str> = route_path.trim_matches('/').split('/').collect();

    if req_parts.len() != route_parts.len() {
        return None;
    }

    for (i, route_part) in route_parts.iter().enumerate() {
        if route_part.starts_with(':') && &route_part[1..] == key {
            return req_parts.get(i).and_then(|v| v.parse::<T>().ok());
        }
    }

    None
}

pub fn get_query<T>(request: &Request, key: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|param| {
            let mut parts = param.splitn(2, '=');
            if parts.next() == Some(key) {
                parts.next().and_then(|v| v.parse::<T>().ok())
            } else {
                None
            }
        })
    })
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

    serde_json::from_reader(whole_body.reader()).map_err(|e| format!("Failed to parse JSON: {}", e))
}
