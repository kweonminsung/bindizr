use http_body_util::Full;
use hyper::{body::Bytes, Response, StatusCode};
use serde_json::Value;
use std::convert::Infallible;

pub fn json_response(
    json_body: Value,
    status: StatusCode,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let body = Bytes::from(json_body.to_string());

    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .status(status)
        .body(Full::new(body))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::StatusCode;
    use serde_json::json;

    #[tokio::test]
    async fn test_json_response() {
        let json_body = json!({"key": "value"});
        let response = json_response(json_body.clone(), StatusCode::OK).unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "application/json"
        );

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(parsed, json_body);
    }
}
