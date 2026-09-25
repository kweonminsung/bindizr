use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

mod bulk;

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

/// Verify record creation, retrieval, update, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_read_update_delete() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let create_record_request = json!({
        "name": "api",
        "type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_name": zone_name
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let record_id = body["record"]["id"].as_i64().unwrap();
    assert_eq!(body["record"]["name"], format!("api.{zone_name}."));
    assert_eq!(body["record"]["type"], "A");

    let (status, body) = app
        .send_request(Method::GET, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], format!("api.{zone_name}."));

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    // The type filter parses at the service boundary, so junk is a 400
    // rather than an empty page.
    let (status, _) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&type=BOGUS"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let update_record_request = json!({
        "name": "api-updated",
        "type": "A",
        "value": "192.168.1.202",
        "ttl": 3600
    });
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(update_record_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], format!("api-updated.{zone_name}."));
    assert_eq!(body["record"]["value"], "192.168.1.202");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(json!({ "ttl": 600 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["ttl"], 600);
    assert_eq!(body["record"]["name"], format!("api-updated.{zone_name}."));
    assert_eq!(body["record"]["value"], "192.168.1.202");

    let (status, _) = app
        .send_request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .send_request(Method::GET, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Verify zone-name normalization in record requests.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_normalize_zone_name() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("example.com");

    let create_zone_request = json!({
        "name": format!("{}.", zone_name.to_ascii_uppercase()),
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600
    });
    let (status, body) = app
        .send_request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["name"], zone_name);

    let create_record_request = json!({
        "name": "api",
        "type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_name": format!("{}.", zone_name.to_ascii_uppercase())
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], format!("api.{zone_name}."));
    assert_eq!(body["record"]["zone_name"], zone_name);
}

/// Verify that record delete matching moves the zone by one serial.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_delete_matching_moves_the_zone_by_one_serial() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for address in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": "www", "type": "A", "value": address, "zone_name": zone_name
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www", "type": "TXT", "value": "keep", "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let serial_of = async |app: &TestApp| -> i64 {
        let (_, body) = app
            .send_request(Method::GET, &format!("/zones?name={zone_name}"), None)
            .await;
        body["items"][0]["serial"].as_i64().unwrap()
    };
    let before = serial_of(&app).await;

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=www&type=A&dry_run=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], 3, "{body}");
    assert_eq!(body["applied"], false, "{body}");
    assert_eq!(serial_of(&app).await, before, "a dry run must not move it");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=www&type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], 3, "{body}");

    // Row by row would bump it three times and serve the half-removed RRset.
    assert_eq!(serial_of(&app).await, before + 1);

    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    let kept: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kept,
        ["TXT"],
        "another type at the name is not every record of the name and type"
    );

    // Matching nothing leaves the zone where it is, so a retry is free.
    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=www&type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], 0, "{body}");
    assert_eq!(serial_of(&app).await, before + 1);
}

/// Verify that record delete matching refuses what would widen it.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_delete_matching_refuses_what_would_widen_it() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The last would be a whole-zone delete; the other cannot be meant.
    for (query, expected) in [
        (
            format!("/records?zone_name={zone_name}&name=www&value=x"),
            "record_type is required",
        ),
        (format!("/records?zone_name={zone_name}"), "name"),
    ] {
        let (status, body) = app.send_request(Method::DELETE, &query, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        assert!(
            body["error"].as_str().unwrap().contains(expected),
            "{query}: {body}"
        );
    }
}

/// Verify that a TXT record goes by the value it was created with.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_delete_matches_a_txt_value_as_the_content_it_was_created_with() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // These quotes are data, not delimiters, so the delete has to be given
    // the same string the create was.
    let value = "\"hello\"";
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www", "type": "TXT", "value": value, "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=www&type=TXT&value=%22hello%22"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"].as_i64(), Some(1), "{body}");

    // Several character-strings are named the way a create names them, and
    // every one has to match: a subset names no record.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "seg", "type": "TXT", "value": ["hello", "world"],
                "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=seg&type=TXT&value=hello"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"].as_i64(), Some(0), "{body}");

    // A value naming no record removes none: reading the same string the other
    // way would delete whichever record that spelling happens to name.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "plain", "type": "TXT", "value": "hello", "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=plain&type=TXT&value=%22hello%22"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"].as_i64(), Some(0), "{body}");
}

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

/// Verify that a non-ASCII label is refused with the punycode advice.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_non_ascii_label_is_refused_with_punycode_advice() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Owner names and the names inside values take the A-label form the wire
    // carries (RFC 5890): the raw label is refused, its A-label accepted.
    for (name, record_type, value, expected) in [
        ("caf\u{e9}", "A", "192.0.2.1", StatusCode::BAD_REQUEST),
        (
            "alias",
            "CNAME",
            "caf\u{e9}.example.",
            StatusCode::BAD_REQUEST,
        ),
        ("xn--caf-dma", "A", "192.0.2.1", StatusCode::CREATED),
        (
            "alias",
            "CNAME",
            "xn--caf-dma.example.",
            StatusCode::CREATED,
        ),
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
        assert_eq!(status, expected, "{name} {record_type} {value}: {body}");
        if expected == StatusCode::BAD_REQUEST {
            assert!(body.to_string().contains("punycode"), "{body}");
        }
    }
}

/// Verify that a control character in a TXT value is stored escaped.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_control_character_in_a_txt_value_is_stored_escaped() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // RFC 1035, Section 5.1 lets a TXT carry any octet; the display column
    // holds the NUL as `\000`, which is also how a search reaches it.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "nul",
                "type": "TXT",
                "value": "a\u{0}b",
                "zone_name": zone_name,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&type=TXT&search=%5C000"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().map(Vec::len), Some(1), "{body}");
}

/// Verify that a NAPTR regexp BIND refuses is rejected.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_naptr_regexp_bind_refuses_is_rejected() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // BIND checks the regexp on receipt, and one record it refuses fails the
    // whole zone transfer, so what it refuses must not be stored. A backslash
    // in the regexp is spelled `\\` in the quoted form (RFC 1035, Section 5.1).
    for (value, expected) in [
        (
            "10 10 \"u\" \"E2U+sip\" \"garbage\" .",
            StatusCode::BAD_REQUEST,
        ),
        (
            "10 10 \"u\" \"E2U+sip\" \"!^.*$!sip:a\\000b@example.com!\" .",
            StatusCode::BAD_REQUEST,
        ),
        (
            "10 10 \"u\" \"E2U+sip\" \"!^.*$!sip:info@example.com!x\" .",
            StatusCode::BAD_REQUEST,
        ),
        (
            "10 10 \"u\" \"E2U+sip\" \"!^.*$!sip:\\\\1@example.com!\" .",
            StatusCode::BAD_REQUEST,
        ),
        (
            "10 10 \"u\" \"E2U+sip\" \"!^\\\\+1(.*)$!sip:\\\\1@example.com!i\" .",
            StatusCode::CREATED,
        ),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": "probe",
                    "type": "NAPTR",
                    "value": value,
                    "zone_name": zone_name,
                })),
            )
            .await;
        assert_eq!(status, expected, "{value}: {body}");
        if expected == StatusCode::BAD_REQUEST {
            assert!(body.to_string().contains("NAPTR regexp"), "{body}");
        }
    }
}

/// Verify that invalid record values are rejected.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_invalid_values() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    for (record_type, value, expected_error) in [
        ("A", "not-an-ip", "valid IPv4"),
        ("AAAA", "192.168.1.1", "valid IPv6"),
        (
            "CNAME",
            "bad target.example.com",
            "must not contain whitespace",
        ),
        ("CNAME", "bad..example.com", "must not contain empty labels"),
    ] {
        let request = json!({
            "name": format!("bad-{}", record_type.to_ascii_lowercase()),
            "type": record_type,
            "value": value,
            "ttl": 1800,
            "zone_name": zone["name"]
        });

        let (status, body) = app
            .send_request(Method::POST, "/records", Some(request))
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"].as_str().unwrap().contains(expected_error),
            "unexpected error for {record_type} value '{value}': {}",
            body["error"]
        );
    }

    let valid_request = json!({
        "name": "valid",
        "type": "A",
        "value": "192.0.2.10",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(valid_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();

    let invalid_update = json!({
        "name": "valid",
        "type": "AAAA",
        "value": "not-ipv6",
        "ttl": 1800
    });
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(invalid_update),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("valid IPv6"));
}

/// Verify that records sharing an owner and type must use one TTL.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_mixed_ttl_for_one_name_and_type() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    let first = json!({
        "name": "www",
        "type": "A",
        "value": "192.0.2.1",
        "ttl": 300,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(first))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // RFC 2181, Section 5.2: one TTL per RRset.
    let differing_ttl = json!({
        "name": "www",
        "type": "A",
        "value": "192.0.2.2",
        "ttl": 600,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(differing_ttl))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body["error"].as_str().unwrap().contains("share one TTL"),
        "unexpected error: {}",
        body["error"]
    );

    let matching_ttl = json!({
        "name": "www",
        "type": "A",
        "value": "192.0.2.2",
        "ttl": 300,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(matching_ttl))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // A different type at the same owner name is a separate RRset.
    let other_record_set = json!({
        "name": "www",
        "type": "TXT",
        "value": "hello",
        "ttl": 600,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(other_record_set))
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// Verify rejection of negative TTLs on record creation and update.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_negative_ttl_on_create_and_update() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "neg",
                "type": "A",
                "value": "192.0.2.1",
                "ttl": -1,
                "zone_name": zone["name"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("TTL"), "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "neg",
                "type": "A",
                "value": "192.0.2.1",
                "zone_name": zone["name"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(json!({ "ttl": -1 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("TTL"), "{body}");
}

/// Verify rejection of priority on record types without a priority field.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_priority_on_types_without_one() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    for (record_type, value) in [
        ("A", "192.0.2.1"),
        ("AAAA", "2001:db8::1"),
        ("CNAME", "target.example.com"),
        ("TXT", "hello"),
        ("NS", "ns2.example.com"),
    ] {
        let request = json!({
            "name": if record_type == "NS" { "@" } else { "prio" },
            "type": record_type,
            "value": value,
            "ttl": 3600,
            "priority": 10,
            "zone_name": zone["name"]
        });
        let (status, body) = app
            .send_request(Method::POST, "/records", Some(request))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{record_type}");
        assert!(
            body["error"].as_str().unwrap().contains("priority"),
            "unexpected error for {record_type}: {}",
            body["error"]
        );
    }

    let mx = json!({
        "name": "@",
        "type": "MX",
        "value": "mail.example.com",
        "ttl": 3600,
        "priority": 10,
        "zone_name": zone["name"]
    });
    let (status, _) = app.send_request(Method::POST, "/records", Some(mx)).await;
    assert_eq!(status, StatusCode::CREATED);

    // An update is held to the same rule.
    let a = json!({
        "name": "prio",
        "type": "A",
        "value": "192.0.2.1",
        "ttl": 3600,
        "zone_name": zone["name"]
    });
    let (status, body) = app.send_request(Method::POST, "/records", Some(a)).await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(json!({ "priority": 10 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("priority"),
        "{body}"
    );
}

/// Verify preservation of TXT segment boundaries and case.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_preserve_txt_segments_and_case() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // TXT comparison is byte-exact, so two values differing only in case must
    // coexist under one name instead of colliding as duplicates.
    for value in ["Token=ABC", "Token=abc"] {
        let create_record_request = json!({
            "name": "case-sensitive",
            "type": "TXT",
            "value": value,
            "ttl": 1800,
            "zone_name": zone["name"]
        });

        let (status, _) = app
            .send_request(Method::POST, "/records", Some(create_record_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&value=Token=abc"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["value"], "Token=abc");

    let segmented = json!({
        "name": "segmented",
        "type": "TXT",
        "value": ["a", "bc"],
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(segmented))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["value"], json!(["a", "bc"]));

    let empty_segments = json!({
        "name": "empty-segment-list",
        "type": "TXT",
        "value": [],
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(empty_segments))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("TXT record must contain at least one character-string")
    );

    // A DNS character-string holds at most 255 octets (RFC 1035, Section 3.3), so a
    // 300-char value must be stored split into 255 + 45.
    let long_txt = json!({
        "name": "long-txt",
        "type": "TXT",
        "value": "a".repeat(300),
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(long_txt))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body["record"]["value"],
        json!(["a".repeat(255), "a".repeat(45)])
    );
}

/// Verify owner normalization and rejection of names outside the zone.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_normalize_owner_and_reject_out_of_zone() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let create_record_request = json!({
        "name": "a1",
        "type": "A",
        "value": "127.0.0.1",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], format!("a1.{zone_name}."));

    // The FQDN spelling resolves to the same stored owner as the relative
    // "a1" above, so it must be detected as a duplicate.
    let in_bailiwick_duplicate = json!({
        "name": format!("a1.{zone_name}."),
        "type": "A",
        "value": "127.0.0.1",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(in_bailiwick_duplicate))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let in_bailiwick_different_value = json!({
        "name": format!("a1.{zone_name}"),
        "type": "A",
        "value": "127.0.0.2",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(in_bailiwick_different_value))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], format!("a1.{zone_name}."));

    for name in [
        "a1.",
        "example.net.",
        "a1.example.net.",
        "other.com.",
        "a1.other.com.",
        "badexample.com.",
    ] {
        let out_of_bailiwick = json!({
            "name": name,
            "type": "A",
            "value": "127.0.0.3",
            "ttl": 1800,
            "zone_name": zone["name"]
        });
        let (status, _) = app
            .send_request(Method::POST, "/records", Some(out_of_bailiwick))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name} should be rejected");
    }

    let update_out_of_bailiwick = json!({
        "name": "a1.",
        "type": "A",
        "value": "127.0.0.4",
        "ttl": 1800
    });
    let record_id = body["record"]["id"].as_i64().unwrap();
    let (status, _) = app
        .send_request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(update_out_of_bailiwick),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Verify creation of every supported user record type.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_supported_types() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let record_types = vec![
        ("mail", "MX", "mail.example.com", Some(10)),
        ("_sip._tcp", "SRV", "5 5060 sip.example.com", Some(10)),
        ("@", "TXT", "v=spf1 include:_spf.google.com ~all", None),
        ("ipv6", "AAAA", "2001:db8::1", None),
        ("alias", "CNAME", "www.example.com", None),
        ("@", "CAA", "0 ISSUE letsencrypt.org", None),
        (
            "ssh",
            "SSHFP",
            "4 2 abababababababababababababababababababababababababababababababab",
            None,
        ),
        (
            "_443._tcp",
            "TLSA",
            "3 1 1 abababababababababababababababababababababababababababababababab",
            None,
        ),
    ];

    for (name, record_type, value, priority) in record_types {
        let create_request = json!({
            "name": name,
            "type": record_type,
            "value": value,
            "ttl": 3600,
            "priority": priority,
            "zone_name": zone["name"]
        });

        let (status, body) = app
            .send_request(Method::POST, "/records", Some(create_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["record"]["type"], record_type);
        let expected_value = match record_type {
            "MX" => "mail.example.com.",
            "SRV" => "5 5060 sip.example.com.",
            "CNAME" => "www.example.com.",
            "CAA" => "0 issue \"letsencrypt.org\"",
            "SSHFP" => "4 2 ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
            "TLSA" => "3 1 1 ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
            _ => value,
        };
        assert_eq!(body["record"]["value"], expected_value);

        if let Some(expected_priority) = priority {
            assert_eq!(body["record"]["priority"], expected_priority);
        }
    }

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    // 8 created here + the apex NS record auto-created with the zone.
    assert_eq!(records.len(), 9);
    for record_type in ["MX", "SRV", "TXT", "AAAA", "CNAME", "CAA", "SSHFP", "TLSA"] {
        assert!(
            records.iter().any(|record| record["type"] == record_type),
            "expected {record_type} record in list"
        );
    }
}

/// Verify rejection of records that conflict with a CNAME.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_cname_conflicts() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    let a_record_request = json!({
        "name": "test",
        "type": "A",
        "value": "1.1.1.1",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(a_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let cname_record_request = json!({
        "name": "test",
        "type": "CNAME",
        "value": "other.example.com",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(cname_record_request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let cname_record_request = json!({
        "name": "cname-test",
        "type": "CNAME",
        "value": "another.example.com",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(cname_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let cname_record_id = body["record"]["id"].as_i64().unwrap();

    let a_record_request = json!({
        "name": "cname-test",
        "type": "A",
        "value": "2.2.2.2",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(a_record_request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Renaming the CNAME onto an owner that already holds an A record must
    // hit the same exclusivity check through the update path.
    let update_cname_request = json!({
        "name": "test",
        "type": "CNAME",
        "value": "updated.example.com",
        "ttl": 3600
    });
    let (status, _) = app
        .send_request(
            Method::PUT,
            &format!("/records/{cname_record_id}"),
            Some(update_cname_request),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
