use std::convert::Infallible;

use http_body_util::Full;
use hyper::{body::Bytes, Response, StatusCode};
use serde_json::Value;

pub async fn json_response(
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
