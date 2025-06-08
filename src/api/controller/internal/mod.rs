pub(crate) mod utils;

use http_body_util::{BodyExt, Full};
use hyper::body::{Buf, Bytes};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::{future::Future, pin::Pin};

pub(crate) type Request = hyper::Request<hyper::body::Incoming>;
pub(crate) type Response = Result<hyper::Response<Full<Bytes>>, Infallible>;
pub(crate) type StatusCode = hyper::StatusCode;
pub(crate) type Method = hyper::Method;

pub(crate) struct Route {
    handler: Box<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>,
    middleware: Option<
        Box<
            dyn Fn(Request) -> Pin<Box<dyn Future<Output = Result<Request, Response>> + Send>>
                + Send
                + Sync,
        >,
    >,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct RouteKey {
    method: Method,
    path_pattern: &'static str,
}

pub(crate) struct Router {
    routes: HashMap<RouteKey, Route>,
    not_found: fn() -> Response,
}

impl Router {
    pub(crate) fn new() -> Self {
        Router {
            routes: HashMap::new(),
            not_found: Router::default_not_found,
        }
    }

    pub(crate) async fn route(&self, request: Request) -> Response {
        let path = request.uri().path();
        let method = request.method().clone();

        for (key, route) in &self.routes {
            if method == key.method && Router::match_path(path, key.path_pattern) {
                match &route.middleware {
                    Some(middleware) => match (middleware)(request).await {
                        Ok(modified_request) => {
                            return (route.handler)(modified_request).await;
                        }
                        Err(error) => {
                            return error;
                        }
                    },
                    None => {
                        return (route.handler)(request).await;
                    }
                }
            }
        }

        (self.not_found)()
    }

    fn default_not_found() -> Response {
        let json_body = json!({ "error": "Not Found" });
        utils::json_response(json_body, StatusCode::NOT_FOUND)
    }

    pub(crate) fn register_router(&mut self, router: Router) {
        for (key, route) in router.routes {
            self.routes.insert(key, route);
        }
    }

    pub(crate) fn register_endpoint<Fut>(
        &mut self,
        method: Method,
        path: &'static str,
        handler: fn(Request) -> Fut,
    ) where
        Fut: Future<Output = Response> + Send + 'static,
    {
        let key = RouteKey {
            method,
            path_pattern: path,
        };

        self.routes.insert(
            key,
            Route {
                handler: Box::new(move |req| Box::pin(handler(req))),
                middleware: None,
            },
        );
    }

    pub(crate) fn register_endpoint_with_middleware<Fut, FutMw>(
        &mut self,
        method: Method,
        path: &'static str,
        handler: fn(Request) -> Fut,
        middleware: fn(Request) -> FutMw,
    ) where
        Fut: Future<Output = Response> + Send + 'static,
        FutMw: Future<Output = Result<Request, Response>> + Send + 'static,
    {
        let key = RouteKey {
            method,
            path_pattern: path,
        };

        self.routes.insert(
            key,
            Route {
                handler: Box::new(move |req| Box::pin(handler(req))),
                middleware: Some(Box::new(move |req| Box::pin(middleware(req)))),
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

pub(crate) fn get_param<T>(request: &Request, route_path: &str, key: &str) -> Option<T>
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

pub(crate) fn get_query<T>(request: &Request, key: &str) -> Option<T>
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

pub(crate) async fn get_body<T>(request: Request) -> Result<T, String>
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
