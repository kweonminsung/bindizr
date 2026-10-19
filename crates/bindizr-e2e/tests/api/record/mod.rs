use domain::base::Rtype;
use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, dns::exported_record_sets};

mod bulk;

/// Preserve CAA empty and binary values through record writes and reads.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn caa_values_preserve_empty_and_binary_properties() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let long_tag = format!("0 {} \"\"", "a".repeat(255));
    for (input, expected) in [
        (r#"0 ISSUE """#, r#"0 ISSUE """#),
        (r#"0 issuewild """#, r#"0 issuewild """#),
        (
            r"128 custom \000\255\010\034\092",
            r#"128 custom "\000\255\010\"\\""#,
        ),
        ("0 issue a\\ ", r#"0 issue "a ""#),
        (long_tag.as_str(), long_tag.as_str()),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({"zone_name": zone_name, "name": "@", "type": "CAA", "value": input})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{input}: {body}");
        assert_eq!(body["record"]["value"], expected);
        let id = body["record"]["id"].as_i64().unwrap();
        let path = format!("/records/{id}");
        let (status, body) = app.send_request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["record"]["value"], expected);

        let (status, body) = app
            .send_request(Method::PUT, &path, Some(json!({"value": "0 custom \"\""})))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["record"]["value"], "0 custom \"\"");
        let serial = app.read_zone_serial(zone_name).await;
        for invalid in [
            "0 custom",
            "0 custom a b",
            r"0 custom \256",
            "1 custom x",
            "255 custom x",
        ] {
            let (status, body) = app
                .send_request(Method::PUT, &path, Some(json!({"value": invalid})))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}: {body}");
            assert_eq!(app.read_zone_serial(zone_name).await, serial);
        }
        let (_, body) = app.send_request(Method::GET, &path, None).await;
        assert_eq!(body["record"]["value"], "0 custom \"\"");
        let (status, _) = app.send_request(Method::DELETE, &path, None).await;
        assert_eq!(status, StatusCode::OK);
    }
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

/// Verify record creation, retrieval, update, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_supports_create_read_update_and_delete() {
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
async fn record_canonicalizes_zone_name() {
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

    // Row by row would bump it three times and serve the half-removed record set.
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
async fn record_listing_filters_by_zone() {
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
async fn record_listing_filters_and_paginates() {
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
async fn record_name_filter_matches_owner_spellings_across_zones() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Compose shares its database; unscoped names must be unique per test.
    let suffix = app.namespace();
    let semicolon_owner = format!("foo;bar-{suffix}");
    let dot_owner = format!(r"a\.b-{suffix}");

    for (name, record_type, value) in [
        (semicolon_owner.as_str(), "A", "192.0.2.1"),
        (dot_owner.as_str(), "A", "192.0.2.2"),
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
        semicolon_owner.clone(),
        format!(r"foo\;bar-{suffix}"),
        format!("{semicolon_owner}.{zone_name}."),
        dot_owner.clone(),
        format!(r"a\046b-{suffix}"),
        format!("{dot_owner}.{zone_name}."),
    ] {
        let (status, body) = app
            .send_request(
                Method::GET,
                &format!("/records?name={}", encode(&spelling)),
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

/// Verify that an apex filter maps `@` to the stored empty owner even
/// without a zone from which to construct an FQDN.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn apex_filter_finds_apex_records_without_a_zone_filter() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({"zone_name": zone_name, "name": "www", "type": "A", "value": "192.0.2.1"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

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

    // Keep the unscoped lookup on one page even when Compose retains older runs.
    let (status, unscoped) = app
        .send_request(
            Method::GET,
            &format!("/records?name=@&search={}", app.namespace()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = unscoped["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, [format!("{zone_name}.")]);
}

/// Verify that empty name filter is no filter not the apex.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_listing_ignores_empty_name_filter() {
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

/// Accept DNS octets independently of IDNA host conventions.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_storage_preserves_non_ascii_label_octets() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // UTF-8 input denotes its literal octets; A-labels remain accepted as well.
    for (name, record_type, value, expected) in [
        ("caf\u{e9}", "A", "192.0.2.1", StatusCode::CREATED),
        ("alias", "CNAME", "caf\u{e9}.example.", StatusCode::CREATED),
        ("xn--caf-dma", "A", "192.0.2.1", StatusCode::CREATED),
        (
            "idna-alias",
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
    }
}

/// Verify that a control character in a TXT value is stored escaped.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn txt_record_storage_escapes_control_characters() {
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

/// Reject invalid NAPTR flags on create and update.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn naptr_record_validates_flags_on_create_and_update() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let original = r#"10 10 "uZ9" "app" "" target.example."#;
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "zone_name": zone_name,
                "name": "naptr",
                "type": "NAPTR",
                "value": original,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["record"]["value"], original);
    let id = body["record"]["id"].as_i64().unwrap();
    let before = app.list_records(zone_name).await;
    let serial = app.read_zone_serial(zone_name).await;

    for flags in ["!", "S-", " ", r"\000", r"\033", "é"] {
        for replacement in [".", "target.example."] {
            let invalid = format!("10 10 \"{flags}\" \"app\" \"\" {replacement}");
            for (method, path, request) in [
                (
                    Method::POST,
                    "/records".to_string(),
                    json!({
                        "zone_name": zone_name, "name": "invalid", "type": "NAPTR", "value": invalid,
                    }),
                ),
                (
                    Method::PUT,
                    format!("/records/{id}"),
                    json!({"value": invalid}),
                ),
            ] {
                let (status, body) = app.send_request(method, &path, Some(request)).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{flags}: {body}");
                assert_eq!(body["code"], "INVALID_RECORD_VALUE");
                assert!(
                    body["error"].as_str().unwrap().contains("NAPTR flags"),
                    "{body}"
                );
            }
        }
    }
    assert_eq!(app.list_records(zone_name).await, before);
    assert_eq!(app.read_zone_serial(zone_name).await, serial);
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/records/{id}"),
            Some(json!({"value": r#"10 10 "" "app" "" target.example."#})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["record"]["value"],
        r#"10 10 "" "app" "" target.example."#
    );
}

/// Verify that a NAPTR regexp BIND refuses is rejected.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn naptr_record_rejects_invalid_regexp() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // BIND rejects the whole transfer for an invalid regexp. Literal backslashes
    // use `\\` in quoted text (RFC 1035, Section 5.1).
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
async fn record_rejects_invalid_values() {
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
async fn record_rejects_mixed_ttl_for_one_name_and_type() {
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

    // RFC 2181, Section 5.2: one TTL per record set.
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

    // A different type at the same owner name is a separate record set.
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
async fn record_rejects_negative_ttl_on_create_and_update() {
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
async fn record_rejects_priority_on_types_without_one() {
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
async fn record_preserves_txt_segments_and_case() {
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
async fn record_normalizes_owner_and_rejects_out_of_zone() {
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
async fn record_create_accepts_supported_types() {
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
            "CAA" => "0 ISSUE \"letsencrypt.org\"",
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
async fn record_rejects_cname_conflicts() {
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

/// Verify the DNAME rules of RFC 6672, Section 2.4 and the alias-target rule
/// of RFC 2181, Section 10.3 and RFC 2782, in either order of arrival.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_enforces_dname_and_alias_target_rules() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let create = |name: &str, record_type: &str, value: String, priority: Option<u16>| {
        json!({
            "name": name,
            "type": record_type,
            "value": value,
            "ttl": 3600,
            "priority": priority,
            "zone_name": zone_name
        })
    };

    let cases = [
        // A DNAME keeps other data at its own name, but is a singleton and no delegation.
        (
            "sub",
            "DNAME",
            "one.example.net.".to_string(),
            None,
            StatusCode::CREATED,
        ),
        (
            "sub",
            "A",
            "192.0.2.1".to_string(),
            None,
            StatusCode::CREATED,
        ),
        (
            "sub",
            "DNAME",
            "two.example.net.".to_string(),
            None,
            StatusCode::CONFLICT,
        ),
        (
            "sub",
            "NS",
            "ns.example.net.".to_string(),
            None,
            StatusCode::CONFLICT,
        ),
        (
            "del",
            "NS",
            "ns.example.net.".to_string(),
            None,
            StatusCode::CREATED,
        ),
        (
            "del",
            "DNAME",
            "one.example.net.".to_string(),
            None,
            StatusCode::CONFLICT,
        ),
        // Nothing below a DNAME, whichever arrives first.
        (
            "leaf.sub",
            "A",
            "192.0.2.2".to_string(),
            None,
            StatusCode::CONFLICT,
        ),
        (
            "leaf.top",
            "A",
            "192.0.2.3".to_string(),
            None,
            StatusCode::CREATED,
        ),
        (
            "top",
            "DNAME",
            "one.example.net.".to_string(),
            None,
            StatusCode::CONFLICT,
        ),
        // An NS, MX, or SRV may not name a CNAME of this zone, whichever arrives first.
        (
            "cn",
            "CNAME",
            "www.example.net.".to_string(),
            None,
            StatusCode::CREATED,
        ),
        (
            "@",
            "MX",
            format!("cn.{zone_name}."),
            Some(10),
            StatusCode::CONFLICT,
        ),
        (
            "@",
            "NS",
            format!("cn.{zone_name}."),
            None,
            StatusCode::CONFLICT,
        ),
        (
            "_sip._tcp",
            "SRV",
            format!("5 5060 cn.{zone_name}."),
            Some(10),
            StatusCode::CONFLICT,
        ),
        (
            "@",
            "MX",
            "mail.example.net.".to_string(),
            Some(10),
            StatusCode::CREATED,
        ),
        (
            "@",
            "MX",
            format!("mx2.{zone_name}."),
            Some(20),
            StatusCode::CREATED,
        ),
        (
            "mx2",
            "CNAME",
            "www.example.net.".to_string(),
            None,
            StatusCode::CONFLICT,
        ),
    ];
    for (name, record_type, value, priority, expected) in cases {
        for dry_run in [true, false] {
            let mut request = create(name, record_type, value.clone(), priority);
            request["dry_run"] = json!(dry_run);
            let (status, body) = app
                .send_request(Method::POST, "/records", Some(request))
                .await;
            let expected = if dry_run && expected == StatusCode::CREATED {
                StatusCode::OK
            } else {
                expected
            };
            assert_eq!(
                status, expected,
                "{name} {record_type} {value}, dry_run={dry_run}: {body}"
            );
        }
    }

    // A DNAME at the apex is allowed beside the zone's own SOA and NS, and
    // then nothing else may exist in the zone.
    let apex_zone_name = app.zone_name("apex-dname.example");
    app.create_zone_cli(&apex_zone_name, "3600").await;
    for (name, record_type, expected) in [
        ("@", "DNAME", StatusCode::CREATED),
        ("host", "A", StatusCode::CONFLICT),
    ] {
        let value = if record_type == "A" {
            "192.0.2.4"
        } else {
            "one.example.net."
        };
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": name,
                    "type": record_type,
                    "value": value,
                    "ttl": 3600,
                    "zone_name": apex_zone_name
                })),
            )
            .await;
        assert_eq!(status, expected, "{name} {record_type}: {body}");
    }
}

/// Preview and apply reject the same cross-owner conflicts without changing the zone.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_mutations_validate_the_complete_proposed_state() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (status, seeded) = app
        .send_request(
            Method::POST,
            "/records/bulk",
            Some(json!({
                "zone_name": zone_name,
                "records": [
                    {"name": "child", "type": "NS", "value": "ns.example.net."},
                    {"name": "child", "type": "DS", "value": "12345 13 2 abababababababababababababababababababababababababababababababab"},
                    {"name": "redirect", "type": "DNAME", "value": "target.example.net."}
                ]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{seeded}");
    let ns_id = seeded["records"][0]["id"].as_i64().unwrap();
    let serial = app.read_zone_serial(zone_name).await;
    for dry_run in [true, false] {
        let (status, body) = app
            .send_request(
                Method::PUT,
                &format!("/records/{ns_id}"),
                Some(json!({"name": "moved", "dry_run": dry_run})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        for path in [
            format!("/records/{ns_id}?dry_run={dry_run}"),
            format!("/records?zone_name={zone_name}&name=child&type=NS&dry_run={dry_run}"),
        ] {
            let (status, body) = app.send_request(Method::DELETE, &path, None).await;
            assert_eq!(status, StatusCode::CONFLICT, "{body}");
        }
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records/bulk",
                Some(json!({
                    "zone_name": zone_name, "dry_run": dry_run,
                    "records": [{"name": "leaf.redirect", "type": "A", "value": "192.0.2.5"}]
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("/zones/{zone_name}/import"),
                Some(json!({
                    "content": "leaf.redirect IN A 192.0.2.5\n", "dry_run": dry_run
                })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["applied"], false);
        assert!(!body["errors"].as_array().unwrap().is_empty());
        assert_eq!(app.read_zone_serial(zone_name).await, serial);
    }
    // Removing the delegation and its DS together leaves a valid final state.
    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=child"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], 2);
}

/// Verify that records listing signed pages the derived plane.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn signed_record_listing_paginates_derived_records() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www",
                "type": "A",
                "value": "192.0.2.10",
                "zone_name": zone_name,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let user_total = body["pagination"]["total"].as_u64().unwrap();
    assert!(
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["id"].is_i64()),
        "the unsigned listing holds only addressable user records"
    );

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&signed=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(
        body["pagination"]["total"].as_u64().unwrap() as usize,
        items.len()
    );
    assert!(body["pagination"]["total"].as_u64().unwrap() > user_total);
    assert!(items.iter().any(|item| item["id"].is_i64()));
    for item in items {
        assert_eq!(item["zone_name"], zone_name);
        assert!(item["name"].as_str().unwrap().ends_with('.'));
    }
    let derived: Vec<_> = items.iter().filter(|item| item["id"].is_null()).collect();
    for record_type in ["DNSKEY", "NSEC3", "RRSIG"] {
        assert!(
            derived.iter().any(|item| item["type"] == record_type),
            "signed listing must carry a {record_type} row: {items:?}"
        );
    }
    assert!(derived.iter().all(|item| item["priority"].is_null()));

    // The derived plane pages after the user records under one offset space.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&signed=true&offset={user_total}&limit=2"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|item| item["id"].is_null()));

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&signed=true&type=RRSIG"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert!(!items.is_empty());
    assert!(items.iter().all(|item| item["type"] == "RRSIG"));

    // A derived type is only addressable through the signed view.
    let (status, _) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&type=RRSIG"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Verify that a signed listing searches the derived plane by name.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn signed_record_listing_filters_derived_records_by_name() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "searchable", "type": "A", "value": "192.0.2.1",
                "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The search must reach the derived rows, not only the stored ones.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&search=searchable&signed=true&limit=1000"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let types: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"A"), "{body}");
    assert!(types.contains(&"RRSIG"), "{body}");

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&search=caf%C3%A9&signed=true&type=RRSIG"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["items"].as_array().unwrap().is_empty(), "{body}");
    assert_eq!(body["pagination"]["total"], 0);

    // Refused rather than quietly answered without the rows it cannot narrow.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&value=192.0.2.1&signed=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("value cannot narrow the derived"),
        "{body}"
    );
}

/// Binary TXT and generic types retain their exact RDATA when API responses are written back.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn binary_txt_and_unknown_types_round_trip() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone = zone["name"].as_str().unwrap();
    for (name, rtype, value, bytes) in [
        (
            "binary",
            "TXT",
            json!({"presentation": r#""\255\000" "\195" "\169""#}),
            vec![2, 255, 0, 1, 195, 1, 169],
        ),
        ("empty", "TYPE65280", json!(r"\# 0"), vec![]),
        (
            "other",
            "TYPE65281",
            json!(r"\# 4 00ff C00C"),
            vec![0, 255, 192, 12],
        ),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({"zone_name": zone, "name": name, "type": rtype, "value": value})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let path = format!("/records/{}", body["record"]["id"]);
        let value = body["record"]["value"].clone();
        let (status, body) = app
            .send_request(Method::PUT, &path, Some(json!({"value": value})))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let wire_type: Rtype = rtype.parse().unwrap();
        assert_eq!(
            exported_record_sets(&app, zone)
                .await
                .get(&(format!("{name}.{zone}."), wire_type))
                .unwrap(),
            &vec![bytes]
        );
    }
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone}/import"),
            Some(json!({"content": r#"imported IN TXT "\255\000""#})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        exported_record_sets(&app, zone)
            .await
            .get(&(format!("imported.{zone}."), Rtype::TXT))
            .unwrap(),
        &vec![vec![2, 255, 0]]
    );
}

/// PTR cannot name a CNAME, whichever record was created first (RFC 2181, Section 10.2).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn ptr_record_rejects_alias_target() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone = zone["name"].as_str().unwrap();
    for reverse in [false, true] {
        let alias = if reverse { "later" } else { "earlier" };
        let cname = json!({"zone_name": zone, "name": alias, "type": "CNAME", "value": "host.example.net."});
        let ptr = json!({"zone_name": zone, "name": format!("ptr-{alias}"), "type": "PTR", "value": format!("{alias}.{zone}.")});
        let [first, second] = if reverse { [ptr, cname] } else { [cname, ptr] };
        assert_eq!(
            app.send_request(Method::POST, "/records", Some(first))
                .await
                .0,
            StatusCode::CREATED
        );
        let (status, body) = app
            .send_request(Method::POST, "/records", Some(second))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    }
}

/// Record TTLs survive API, filters, history, export and transfer import over the full wire range.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_ttl_preserves_unsigned_boundaries() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    for (index, ttl) in [0i64, 2_147_483_647, 2_147_483_648, i64::from(u32::MAX)]
        .into_iter()
        .enumerate()
    {
        let name = format!("ttl{index}");
        let (status, body) = app.send_request(Method::POST, "/records", Some(json!({
            "zone_name": zone_name, "name": name, "type": "A", "value": "192.0.2.44", "ttl": ttl
        }))).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["record"]["ttl"], ttl);
        if ttl > 0 {
            let (status, body) = app
                .send_request(
                    Method::PUT,
                    &format!("/zones/{zone_name}"),
                    Some(json!({"minimum_ttl": ttl})),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["zone"]["minimum_ttl"], ttl);
        }
        let serial = app.read_zone_serial(zone_name).await;
        let (status, body) = app
            .send_request(
                Method::GET,
                &format!("/zones/{zone_name}/versions/{serial}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["name"] == format!("{name}.{zone_name}.") && row["ttl"] == ttl),
            "{body}"
        );
        let (status, body) = app
            .send_request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&ttl={ttl}&min_ttl={ttl}&max_ttl={ttl}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
    }
    let serial = app.read_zone_serial(zone_name).await;
    for ttl in [-1i64, i64::from(u32::MAX) + 1] {
        let (status, body) = app.send_request(Method::POST, "/records", Some(json!({
            "zone_name": zone_name, "name": "invalid", "type": "A", "value": "192.0.2.45", "ttl": ttl
        }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(app.read_zone_serial(zone_name).await, serial);
    }
    app.create_secondary("ttl-loopback", "127.0.0.1").await;
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({
                "from_server": format!("127.0.0.1:{}", app.dns_port()), "mode": "replace"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"]["unchanged"], 5);
    let records = app.list_records(zone_name).await;
    for ttl in [0i64, 2_147_483_647, 2_147_483_648, i64::from(u32::MAX)] {
        assert!(
            records
                .iter()
                .any(|record| record["type"] == "A" && record["ttl"] == ttl)
        );
    }
}
