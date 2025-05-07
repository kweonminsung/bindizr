use std::convert::Infallible;

use http_body_util::Full;
use hyper::{body::Bytes, Response, StatusCode};
use serde_json::Value;

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

pub fn get_query_param(
    request: &hyper::Request<hyper::body::Incoming>,
    key: &str,
) -> Option<String> {
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
