use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

/// Keep SOA minimum bounds aligned across the live schema and zone writes.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn minimum_ttl_schema_matches_zone_write_boundaries() {
    let app = TestApp::start_with_options(TestAppOptions {
        openapi_enabled: true,
        ..Default::default()
    })
    .await;
    let (status, document) = app.send_request(Method::GET, "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    for schema in ["CreateZoneRequest", "UpdateZoneRequest"] {
        let minimum = &document["components"]["schemas"][schema]["properties"]["minimum_ttl"];
        assert_eq!(minimum["minimum"], 0, "{schema}");
        assert_eq!(minimum["maximum"], u32::MAX, "{schema}");
    }
    let zone = app.create_test_zone().await;
    for ttl in [-1, 0, i64::from(u32::MAX), i64::from(u32::MAX) + 1] {
        let name = app.zone_name(&format!("minimum-{}.example", ttl + 1));
        let accepted = (0..=i64::from(u32::MAX)).contains(&ttl);
        let (status, body) = app.send_request(Method::POST, "/zones", Some(json!({
            "name": name, "mname": "ns.example.com", "rname": "admin@example.com", "minimum_ttl": ttl
        }))).await;
        assert_eq!(
            status,
            if accepted {
                StatusCode::CREATED
            } else {
                StatusCode::BAD_REQUEST
            },
            "{ttl}: {body}"
        );
        if accepted {
            assert_eq!(body["zone"]["minimum_ttl"], ttl);
        }
        let (status, body) = app
            .send_request(
                Method::PUT,
                &format!("/zones/{}", zone["name"].as_str().unwrap()),
                Some(json!({"minimum_ttl": ttl})),
            )
            .await;
        assert_eq!(
            status,
            if accepted {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            "{ttl}: {body}"
        );
        if accepted {
            assert_eq!(body["zone"]["minimum_ttl"], ttl);
        }
    }
}

/// Verify that the unauthenticated API description is disabled by default.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_omits_document_when_disabled() {
    let app = TestApp::start_local().await;

    for path in ["/openapi.json", "/openapi.yaml"] {
        let (status, _) = app.send_request(Method::GET, path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

/// Verify that enabled JSON and YAML API descriptions need no token.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_serves_documents_without_token_when_enabled() {
    let app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        openapi_enabled: true,
        ..Default::default()
    })
    .await;

    let (status, body) = app.send_request(Method::GET, "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["paths"]["/zones"]["get"].is_object());
    let optional_serial =
        &body["components"]["schemas"]["CreateZoneRequest"]["properties"]["serial"];
    assert_eq!(optional_serial["oneOf"][1]["type"], "null");
    let serial = &optional_serial["oneOf"][0];
    assert_eq!(serial["minimum"], 0);
    assert_eq!(serial["maximum"], u32::MAX);
    assert_eq!(serial["format"], "int64");
    assert_eq!(serial["examples"][0], 42);
    assert_eq!(
        &body["components"]["schemas"]["ZoneResponse"]["properties"]["serial"],
        serial
    );
    for (path, item) in body["paths"].as_object().unwrap() {
        for operation in item.as_object().unwrap().values() {
            let Some(parameters) = operation["parameters"].as_array() else {
                continue;
            };
            for parameter in parameters {
                let ttl_filter = matches!(
                    parameter["name"].as_str(),
                    Some(
                        "ttl"
                            | "min_ttl"
                            | "max_ttl"
                            | "default_ttl"
                            | "min_default_ttl"
                            | "max_default_ttl"
                    )
                );
                if ttl_filter {
                    assert_eq!(parameter["required"], false, "{path}");
                }
                if ttl_filter
                    || matches!(
                        parameter["name"].as_str(),
                        Some("serial" | "min_serial" | "max_serial")
                    )
                    || (path == "/zones/{name}/versions/diff"
                        && matches!(parameter["name"].as_str(), Some("from" | "to")))
                {
                    assert_eq!(parameter["schema"]["minimum"], 0, "{path}");
                    assert_eq!(parameter["schema"]["maximum"], u32::MAX, "{path}");
                    assert_eq!(parameter["schema"]["format"], "int64", "{path}");
                }
            }
        }
    }
    for name in [
        "CreateRecordRequest",
        "UpdateRecordRequest",
        "BulkRecordItem",
        "ExternalDnsRecord",
    ] {
        let ttl = &body["components"]["schemas"][name]["properties"]["ttl"];
        let alternatives = ttl["oneOf"].as_array().expect("TTL accepts null");
        assert!(alternatives.iter().any(|schema| schema["type"] == "null"));
        let integer = alternatives
            .iter()
            .find(|schema| schema["type"] == "integer")
            .unwrap();
        assert_eq!(integer["minimum"], 0, "{name}");
        assert_eq!(integer["maximum"], u32::MAX, "{name}");
        assert_eq!(integer["format"], "int64", "{name}");
    }
    for name in ["CreateZoneRequest", "UpdateZoneRequest"] {
        let minimum = &body["components"]["schemas"][name]["properties"]["minimum_ttl"];
        assert_eq!(minimum["minimum"], 0, "{name}");
        assert_eq!(minimum["maximum"], u32::MAX, "{name}");
    }
    let record_type = &body["components"]["schemas"]["RecordType"];
    assert_eq!(record_type["type"], "string");
    let supported_types = record_type["enum"].as_array().unwrap();
    assert_eq!(supported_types.len(), 15);
    assert!(supported_types.iter().any(|name| name == "WKS"));
    assert!(!supported_types.iter().any(|name| name == "TYPE65280"));
    for name in ["ImportZoneRequest", "ImportZonesRequest"] {
        assert!(
            body["components"]["schemas"][name]["properties"]
                .get("skip_unsupported")
                .is_none()
        );
    }
    assert!(
        body["components"]["schemas"]["ImportZoneResponse"]["properties"]
            .get("skipped_records")
            .is_none()
    );
    assert!(
        body["components"]["schemas"]["RecordValue"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|shape| shape["properties"]["presentation"]["type"] == "string")
    );
    assert!(
        body["components"]["schemas"]["UpdateZoneRequest"]["properties"]
            .get("serial")
            .is_none()
    );

    // YAML is not JSON, so the harness hands it back as a plain string.
    let (status, body) = app.send_request(Method::GET, "/openapi.yaml", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.as_str().is_some_and(|yaml| yaml.contains("openapi:")),
        "YAML document was not served"
    );
}

/// Keep documented page limits aligned with the API's accepted query values.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn pagination_limits_match_the_openapi_contract() {
    let app = TestApp::start_with_options(TestAppOptions {
        openapi_enabled: true,
        ..Default::default()
    })
    .await;

    let (status, document) = app.send_request(Method::GET, "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    for (path, item) in document["paths"].as_object().unwrap() {
        let Some(parameters) = item["get"]["parameters"].as_array() else {
            continue;
        };
        for parameter in parameters {
            if parameter["name"] == "limit" && parameter["in"] == "query" {
                assert_eq!(parameter["schema"]["minimum"], 1, "{path}");
                assert_eq!(parameter["schema"]["maximum"], 1000, "{path}");
            }
        }
    }

    for path in ["/zones", "/tokens"] {
        let (status, body) = app.send_request(Method::GET, path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        assert_eq!(body["pagination"]["limit"], 50, "{path}");

        for (limit, expected_status) in [
            (0, StatusCode::BAD_REQUEST),
            (1, StatusCode::OK),
            (1000, StatusCode::OK),
            (1001, StatusCode::BAD_REQUEST),
        ] {
            let url = format!("{path}?limit={limit}");
            let (status, body) = app.send_request(Method::GET, &url, None).await;
            assert_eq!(status, expected_status, "{url}: {body}");
            if status == StatusCode::OK {
                assert_eq!(body["pagination"]["limit"], limit, "{url}");
            } else {
                assert_eq!(body["code"], "INVALID_INPUT", "{url}: {body}");
            }
        }
    }
}
