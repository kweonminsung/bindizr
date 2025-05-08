use std::convert::Infallible;

use http_body_util::Full;
use hyper::{body::Bytes, Response, StatusCode};
use serde_json::Value;

pub fn match_path(request_path: &str, route_path: &str) -> bool {
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

pub fn json_response(
    json_body: Value,
    status: StatusCode,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = Bytes::from(json_body.to_string());

    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .status(status)
        .body(Full::new(body))
        .unwrap())
}

pub fn get_param(
    request: &hyper::Request<hyper::body::Incoming>,
    route_path: &str,
    key: &str,
) -> Option<String> {
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
                return Some(req_part.to_string());
            }
        }
    }

    None
}

pub fn get_query(request: &hyper::Request<hyper::body::Incoming>, key: &str) -> Option<String> {
    let query = request.uri().query()?;
    let params: Vec<&str> = query.split('&').collect();
    for param in params {
        let pair: Vec<&str> = param.split('=').collect();
        if pair.len() == 2 && pair[0] == key {
            return Some(pair[1].to_string());
        }
    }
    None
}
