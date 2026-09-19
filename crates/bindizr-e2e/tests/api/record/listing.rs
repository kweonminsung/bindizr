use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify that record listings are scoped to the requested zone.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_scope_by_zone() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let first_zone_name = zone["name"].as_str().unwrap();
    let second_zone_name = app.zone_name("example.net");

    let second_zone = json!({
        "name": second_zone_name,
        "mname": format!("ns1.{second_zone_name}"),
        "rname": "admin@example.net",
        "default_ttl": 3600
    });
    let (status, _) = app
        .send_request(Method::POST, "/zones", Some(second_zone))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let mut second_record_id = None;
    for (zone_name, value) in [
        (first_zone_name, "192.0.2.10"),
        (second_zone_name.as_str(), "192.0.2.20"),
    ] {
        let create_record_request = json!({
            "name": "shared",
            "type": "A",
            "value": value,
            "ttl": 1800,
            "zone_name": zone_name
        });

        let (status, body) = app
            .send_request(Method::POST, "/records", Some(create_record_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
        if zone_name == second_zone_name {
            second_record_id = Some(body["record"]["id"].as_i64().unwrap());
        }
    }

    let second_record_id = second_record_id.unwrap();

    let (status, body) = app
        .send_request(Method::GET, &format!("/records/{second_record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["value"], "192.0.2.20");

    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/records/{second_record_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={first_zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |record| record["name"] == format!("shared.{first_zone_name}.")
                    && record["value"] == "192.0.2.10"
            )
    );

    let (status, _) = app
        .send_request(Method::GET, &format!("/records/{second_record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Verify record filtering and pagination.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_filter_and_paginate() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for request in [
        json!({
            "name": "api",
            "type": "A",
            "value": "192.168.1.200",
            "ttl": 1800,
            "zone_name": zone["name"]
        }),
        json!({
            "name": "mail",
            "type": "MX",
            "value": "mail.example.com",
            "ttl": 3600,
            "priority": 10,
            "zone_name": zone["name"]
        }),
        json!({
            "name": "alias",
            "type": "CNAME",
            "value": "Target.Example.Com",
            "ttl": 7200,
            "zone_name": zone["name"]
        }),
    ] {
        let (status, _) = app
            .send_request(Method::POST, "/records", Some(request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&value=168.1&min_ttl=1000&max_ttl=2000"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], format!("api.{zone_name}."));

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&search=mail&min_priority=5&max_priority=15"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["type"], "MX");

    // The CNAME was created as "Target.Example.Com": the value filter matches
    // against the normalized (lowercased, dot-terminated) stored value.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&value=target.example.com"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["type"], "CNAME");

    // Filters accept denormalized inputs too: a trailing-dot zone name and an
    // owner in FQDN form without the trailing dot.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}.&name=api.{zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], format!("api.{zone_name}."));

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&limit=1&offset=2"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], format!("api.{zone_name}."));
    assert_eq!(body["pagination"]["total"], 4);
    assert_eq!(body["pagination"]["limit"], 1);
    assert_eq!(body["pagination"]["offset"], 2);

    let (status, _) = app
        .send_request(Method::GET, "/records?offset=-1", None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Verify that record filter matches every spelling of an owner name.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_filter_matches_every_spelling_of_an_owner_name() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for name in ["www", "foo;bar"] {
        let (status, _) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": name,
                    "type": "A",
                    "value": "192.0.2.1",
                    "zone_name": zone_name,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{name}");
    }

    // The apex is the empty name in a row, and `;` is escaped there.
    for spelling in [
        "@",
        "www",
        &format!("www.{zone_name}."),
        "foo;bar",
        r"foo\;bar",
    ] {
        let (status, body) = app
            .send_request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&name={}", encode(spelling)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["items"].as_array().map(Vec::len),
            Some(1),
            "no record matched {spelling:?}"
        );
    }
}

/// Verify that a name filter without a zone reads the same spellings.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_name_filter_without_a_zone_reads_the_same_spellings() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for (name, record_type, value) in [
        ("foo;bar", "A", "192.0.2.1"),
        (r"a\.b", "A", "192.0.2.2"),
        ("note", "TXT", "caf\u{e9}"),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": name,
                    "type": record_type,
                    "value": value,
                    "zone_name": zone_name,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    // Without a zone the filter is still rendered as rows hold it: a relative
    // name against the owner, an absolute one against the FQDN.
    for spelling in [
        "foo;bar",
        r"foo\;bar",
        &format!("foo;bar.{zone_name}."),
        r"a\.b",
        r"a\046b",
        &format!(r"a\.b.{zone_name}."),
    ] {
        let (status, body) = app
            .send_request(
                Method::GET,
                &format!("/records?name={}", encode(spelling)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["items"].as_array().map(Vec::len),
            Some(1),
            "no record matched {spelling:?}: {body}"
        );
    }

    // A search term is text: a TXT value holding it is found as typed.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!(
                "/records?zone_name={zone_name}&search={}",
                encode("caf\u{e9}")
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().map(Vec::len), Some(1), "{body}");
}

/// Percent-encode a query value byte by byte; `;`, `\` and UTF-8 would
/// otherwise be taken apart.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// Verify that an apex filter works without a zone filter.
///
/// Without a zone to construct an FQDN, `@` must map to the empty-string owner stored in apex
/// rows.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn apex_filter_finds_apex_records_without_a_zone_filter() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, scoped) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=@"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let scoped_count = scoped["items"].as_array().unwrap().len();
    assert!(
        scoped_count > 0,
        "zone has no apex record to find: {scoped}"
    );

    let (status, unscoped) = app.send_request(Method::GET, "/records?name=@", None).await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = unscoped["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&format!("{zone_name}.").as_str()),
        "apex of {zone_name} missing from {names:?}"
    );
}

/// Verify that empty name filter is no filter not the apex.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn empty_name_filter_is_no_filter_not_the_apex() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for (name, value) in [("www", "192.0.2.1"), ("mail", "192.0.2.2")] {
        let (status, _) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": name, "type": "A",
                    "value": value, "zone_name": zone_name
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let count = |body: &serde_json::Value| body["items"].as_array().unwrap().len();

    let (_, unfiltered) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;

    // Rows hold the apex as the empty string, so an empty filter left to fall
    // through would select exactly the apex rows instead of every row.
    let (status, empty) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name="),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count(&empty), count(&unfiltered), "{empty}");
    assert!(count(&empty) > 1, "expected apex plus the two A records");
}

/// Verify that search treats SQL LIKE wildcards as literal characters in owner names and record
/// values.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn search_treats_like_wildcards_as_literal_text() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for (name, value) in [
        ("pct", "100%off"),
        ("pctdecoy", "100XXoff"),
        ("under", "a_b"),
        ("underdecoy", "axb"),
    ] {
        let (status, _) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": name, "type": "TXT",
                    "value": value, "zone_name": zone_name
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    /// Search a zone's records and collect the matching owner labels.
    async fn search(app: &TestApp, zone_name: &str, term: &str) -> Vec<String> {
        let q = term.replace('%', "%25").replace('_', "%5F");
        let (_, body) = app
            .send_request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&search={q}"),
                None,
            )
            .await;
        let mut names: Vec<String> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                r["name"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect();
        names.sort();
        names
    }

    assert_eq!(search(&app, zone_name, "100%off").await, ["pct"]);
    assert_eq!(search(&app, zone_name, "a_b").await, ["under"]);
    // A term that is nothing but wildcards matches the records holding them.
    assert_eq!(search(&app, zone_name, "%").await, ["pct"]);
    assert_eq!(search(&app, zone_name, "_").await, ["under"]);
}

/// Verify that record listing sorts by the field asked for.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_listing_sorts_by_the_field_asked_for() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for (name, ttl) in [("c-rec", 300), ("a-rec", 900), ("b-rec", 60)] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": name, "type": "A", "value": "192.0.2.1",
                    "ttl": ttl, "zone_name": zone_name
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    let listed = async |app: &TestApp, query: &str| -> Vec<String> {
        let (status, body) = app
            .send_request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&type=A&limit=1000&{query}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["name"].as_str().unwrap().to_string())
            .collect()
    };

    let by_ttl = listed(&app, "sort=ttl").await;
    assert!(by_ttl[0].starts_with("b-rec"), "{by_ttl:?}");
    assert!(by_ttl[2].starts_with("a-rec"), "{by_ttl:?}");
    assert_eq!(
        listed(&app, "sort=ttl&order=desc").await,
        by_ttl.iter().rev().cloned().collect::<Vec<_>>()
    );

    let by_name = listed(&app, "").await;
    assert!(by_name[0].starts_with("a-rec"), "{by_name:?}");

    let (status, body) = app
        .send_request(Method::GET, "/records?order=sideways", None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("unknown sort order"),
        "{body}"
    );
}
