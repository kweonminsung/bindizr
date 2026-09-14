use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_filter_and_paginate() {
    let app = TestApp::start().await;
    app.create_test_zone().await;
    let filtered_zone_name = app.zone_name("filtered.net");

    let create_zone_request = json!({
        "name": filtered_zone_name,
        "mname": format!("ns1.{filtered_zone_name}"),
        "rname": "admin@filtered.net",
        "default_ttl": 7200,
        "refresh": 7200,
        "retry": 3600,
        "expire": 604800,
        "minimum_ttl": 86400
    });
    let (status, _) = app
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .request(
            Method::GET,
            &format!(
                "/zones?search={}&min_default_ttl=7000&max_default_ttl=8000",
                app.namespace()
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let zones = body["items"].as_array().unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], filtered_zone_name);

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones?search={}&limit=1&offset=1", app.namespace()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let zones = body["items"].as_array().unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], filtered_zone_name);
    assert_eq!(body["pagination"]["total"], 2);
    assert_eq!(body["pagination"]["limit"], 1);
    assert_eq!(body["pagination"]["offset"], 1);

    let (status, _) = app.request(Method::GET, "/zones?limit=-1", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_listing_sorts_and_filters_on_more_than_the_name() {
    let app = TestApp::start().await;
    let prefix = app.namespace().to_string();

    let mut names = Vec::new();
    for (label, serial) in [("a-sort", 30), ("b-sort", 10), ("c-sort", 20)] {
        let name = app.zone_name(label);
        let (status, body) = app
            .request(
                Method::POST,
                "/zones",
                Some(json!({
                    "name": name,
                    "mname": format!("ns1.{name}"),
                    "rname": "admin@example.com",
                    "default_ttl": 3600,
                    "serial": serial,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        names.push(name);
    }

    let listed = async |app: &TestApp, query: &str| -> Vec<String> {
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/zones?search={prefix}&limit=1000&{query}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|zone| zone["name"].as_str().unwrap().to_string())
            .collect()
    };

    // Creation order is a, b, c; serial order is b, c, a.
    assert_eq!(
        listed(&app, "sort=serial").await,
        [names[1].clone(), names[2].clone(), names[0].clone()]
    );
    assert_eq!(
        listed(&app, "sort=serial&order=desc").await,
        [names[0].clone(), names[2].clone(), names[1].clone()]
    );
    // Omitted, a listing still sorts by name.
    assert_eq!(listed(&app, "").await, names);

    assert_eq!(
        listed(&app, "min_serial=20").await,
        [names[0].clone(), names[2].clone()]
    );
    assert_eq!(listed(&app, "max_serial=10").await, [names[1].clone()]);
    // None of these is signed, so the DNSSEC filter splits them all one way.
    assert!(listed(&app, "signed=true").await.is_empty());
    assert_eq!(listed(&app, "signed=false").await.len(), 3);

    let (status, body) = app.request(Method::GET, "/zones?sort=nope", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("unknown sort field"),
        "{body}"
    );
}
