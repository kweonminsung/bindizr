#![allow(unused_imports)]
use super::*;
use http_body_util::Full;
use std::future::Future;

#[test]
fn test_register_endpoint() {
    let mut router = Router::new();

    router.register_endpoint(Method::GET, "/api/v1/resource", |_: Request| async move {
        Ok(hyper::Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("Resource found")))
            .unwrap())
    });

    let get_route = router.routes.get(&RouteKey {
        method: Method::GET,
        path_pattern: "/api/v1/resource",
    });
    assert!(get_route.is_some());
}

#[test]
fn test_register_endpoint_with_middleware() {
    let mut router = Router::new();

    router.register_endpoint_with_middleware(
        Method::PUT,
        "/api/v1/resource",
        |_: Request| async move {
            Ok(hyper::Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from("Resource updated")))
                .unwrap())
        },
        |req: Request| async move { Ok(req) },
    );

    let put_route = router.routes.get(&RouteKey {
        method: Method::PUT,
        path_pattern: "/api/v1/resource",
    });
    assert!(put_route.is_some());
}

#[test]
fn test_match_path() {
    assert!(Router::match_path("/api/v1/resource", "/api/v1/resource"));
    assert!(Router::match_path("/api/v1/resource/", "/api/v1/resource"));
    assert!(!Router::match_path(
        "/api/v1/resource/extra",
        "/api/v1/resource"
    ));
    assert!(!Router::match_path("/api/v2/resource", "/api/v1/resource"));
    assert!(Router::match_path(
        "/api/v1/resource/123",
        "/api/v1/resource/:id"
    ));
    assert!(Router::match_path(
        "/api/v1/resource/123/details",
        "/api/v1/resource/:id/details"
    ));
}
