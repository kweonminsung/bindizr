use std::convert::Infallible;

use http_body_util::Full;
use hyper::{body::Bytes, Request, Response, StatusCode};
use serde_json::json;

use crate::api::service;
use crate::api::utils;

pub async fn router(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match (request.method(), request.uri().path()) {
        // (&hyper::Method::GET, "/") => get_home(request).await,
        _ => not_found(request).await,
    }
}

async fn get_home(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    dbg!(request);

    utils::json_response(json!({ "msg": "hello world!" }), StatusCode::OK).await
}

async fn not_found(_: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    utils::json_response(json!({ "msg": "404 not found" }), StatusCode::NOT_FOUND).await
}
