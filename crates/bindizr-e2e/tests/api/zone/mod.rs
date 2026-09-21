use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions, probe_zone_soa};

mod history;
mod import;

/// Verify zone creation, retrieval, update, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_read_update_delete() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("test.com");
    let updated_zone_name = app.zone_name("updated-test.com");

    let create_zone_request = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "admin@test.com",
        "default_ttl": 3600,
        "refresh": 7200,
        "retry": 3600,
        "expire": 604800,
        "minimum_ttl": 86400
    });

    let (status, body) = app
        .send_request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let created_zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(created_zone_name, zone_name);

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{created_zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], zone_name);

    // Rename the zone and replace its SOA settings through the original name.
    let update_zone_request = json!({
        "name": updated_zone_name,
        "mname": "ns2.external-dns.net",
        "rname": "admin@updated-test.com",
        "default_ttl": 7200,
        "refresh": 14400,
        "retry": 7200,
        "expire": 1209600,
        "minimum_ttl": 172800
    });

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{created_zone_name}"),
            Some(update_zone_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let actual_updated_zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(actual_updated_zone_name, updated_zone_name);

    // Address the renamed zone and change only TTL; omitted settings must survive.
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{actual_updated_zone_name}"),
            Some(json!({ "default_ttl": 300 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["default_ttl"], 300);
    assert_eq!(body["zone"]["mname"], "ns2.external-dns.net");
    assert_eq!(body["zone"]["rname"], "admin@updated-test.com");
    assert_eq!(body["zone"]["refresh"], 14400);

    // Delete using the new identity and verify that it no longer resolves through the API.
    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/zones/{actual_updated_zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .send_request(
            Method::GET,
            &format!("/zones/{actual_updated_zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Verify serial initialization and rejection of out-of-range serials.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_seed_and_reject_out_of_range_serial() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("seeded-serial.example.com");

    // Secondaries compare serials per RFC 1982, so a takeover has to continue
    // from the previous primary's serial instead of restarting at 1.
    let seeded_zone = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600,
        "serial": 2026072501i64
    });
    let (status, body) = app
        .send_request(Method::POST, "/zones", Some(seeded_zone))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["serial"], 2026072501i64);

    let update_zone_request = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 7200
    });
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(update_zone_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["serial"], 2026072502i64);

    // Past MAX_INITIAL_SERIAL (i32::MAX - 10_000_000) the counter would
    // saturate while the zone is still in use.
    for out_of_range_serial in [0i64, -1, 2_137_483_648, i32::MAX as i64] {
        let out_of_range_zone = json!({
            "name": app.zone_name("out-of-range-serial.example.com"),
            "mname": "ns1.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600,
            "serial": out_of_range_serial
        });
        let (status, _) = app
            .send_request(Method::POST, "/zones", Some(out_of_range_zone))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

/// Verify that zone auto serial starts at one and update rejects explicit serial.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_auto_serial_starts_at_one_and_update_rejects_explicit_serial() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("counter.example");

    let request = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@counter.example",
        "default_ttl": 3600
    });
    let (status, body) = app
        .send_request(Method::POST, "/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["serial"].as_i64().unwrap(), 1);

    let record = json!({
        "name": "www", "type": "A", "value": "192.0.2.70",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(record))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, after) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(after["zone"]["serial"].as_i64().unwrap(), 2);

    let update_with_serial = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@counter.example",
        "default_ttl": 3600,
        "serial": 99
    });
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(update_with_serial),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("managed automatically")
    );
}

/// Verify that version responses and record updates use the apex presentation name.
///
/// Both must translate the empty stored owner: versions render it as `@`, and updates accept
/// `@` or the zone name.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn apex_rows_render_and_update_through_their_presentation_name() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, detail) = app
        .send_request(
            Method::GET,
            &format!("/zones/{zone_name}/versions/{}", zone["serial"]),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = detail["records"]
        .as_array()
        .expect("version records")
        .iter()
        .map(|record| record["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, ["@"], "apex row did not render as the apex");

    let records = app.list_records(zone_name).await;
    let ns = records
        .iter()
        .find(|record| record["type"] == "NS")
        .expect("apex NS row");
    for spelling in ["@", zone_name] {
        let (status, body) = app
            .send_request(
                Method::PUT,
                &format!("/records/{}", ns["id"].as_i64().unwrap()),
                Some(json!({
                    "name": spelling,
                    "type": "NS",
                    "value": ns["value"],
                    "ttl": 1200,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{spelling}: {body}");
    }
}

/// Verify zone filtering and pagination.
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
        .send_request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .send_request(
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
        .send_request(
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

    let (status, _) = app.send_request(Method::GET, "/zones?limit=-1", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Verify that zone listing sorts and filters on more than the name.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_listing_sorts_and_filters_on_more_than_the_name() {
    let app = TestApp::start().await;
    let prefix = app.namespace().to_string();

    let mut names = Vec::new();
    for (label, serial) in [("a-sort", 30), ("b-sort", 10), ("c-sort", 20)] {
        let name = app.zone_name(label);
        let (status, body) = app
            .send_request(
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
            .send_request(
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

    let (status, body) = app
        .send_request(Method::GET, "/zones?sort=nope", None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("unknown sort field"),
        "{body}"
    );
}

/// Verify that a rename keeps every record inside the wire limit.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_rename_keeps_every_record_inside_the_wire_limit() {
    let app = TestApp::start().await;
    let (status, _) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": "a.co",
                "mname": "ns.a.co",
                "rname": "admin@a.co",
                "default_ttl": 3600
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // 249 wire octets under `a.co`, six short of the limit; the seventeen
    // more of `rename-length.example` make it 266.
    let owner = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(50),
    ]
    .join(".");
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": owner,
                "type": "A",
                "value": "192.0.2.1",
                "zone_name": "a.co"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The record was validated under `a.co`; the rename must re-check it, or
    // the zone would commit a name its transfers cannot encode.
    let (status, body) = app
        .send_request(
            Method::PUT,
            "/zones/a.co",
            Some(json!({ "name": "rename-length.example" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("bytes or fewer"), "{body}");
    let (status, _) = app.send_request(Method::GET, "/zones/a.co", None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .send_request(Method::PUT, "/zones/a.co", Some(json!({ "name": "b.co" })))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Verify that a rollback keeps every restored record inside the wire limit.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_rollback_keeps_every_restored_record_inside_the_wire_limit() {
    let app = TestApp::start().await;
    let (status, _) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": "c.co",
                "mname": "ns.c.co",
                "rname": "admin@c.co",
                "default_ttl": 3600
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let owner = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(50),
    ]
    .join(".");
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": owner,
                "type": "A",
                "value": "192.0.2.1",
                "zone_name": "c.co"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let record_id = body["record"]["id"].as_i64().unwrap();
    let (_, zone_at_target) = app.send_request(Method::GET, "/zones/c.co", None).await;
    let target_serial = zone_at_target["zone"]["serial"].as_i64().unwrap();

    // With the long name gone the rename passes; the history still holds it.
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert!(status.is_success(), "{status}");
    let (status, body) = app
        .send_request(
            Method::PUT,
            "/zones/c.co",
            Some(json!({ "name": "rollback-length.example" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Restoring that serial would bring the name back under a zone it no
    // longer fits, so the rollback is refused whole.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/rollback-length.example/versions/{target_serial}/rollback"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("bytes or fewer"), "{body}");
}

/// Verify that a zone cannot take the catalog zone's name, however spelled.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_cannot_take_the_catalog_zone_name() {
    let app = TestApp::start().await;

    for name in ["catalog.bindizr", "Catalog.Bindizr", " catalog.bindizr. "] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/zones",
                Some(json!({
                    "name": name,
                    "mname": "ns1.catalog.bindizr",
                    "rname": "hostmaster@catalog.bindizr",
                    "default_ttl": 3600
                })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "name: {name}");
        assert!(
            body.to_string().contains("catalog zone name"),
            "name: {name}, body: {body}"
        );
    }
}

/// Verify zone-field validation and normalization.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_validate_and_normalize() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("test.example.com");
    let second_zone_name = app.zone_name("second.example.com");

    // The second entry is already in SOA-mailbox form: the API accepts email
    // addresses only and must not pass a mailbox through untranslated.
    for invalid_rname in [
        json!({
            "name": "invalid-rname.com",
            "mname": "ns1.invalid-rname.com",
            "rname": "admin@@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "soa-mailbox.com",
            "mname": "ns1.soa-mailbox.com",
            "rname": "hostmaster.soa-mailbox.com.",
            "default_ttl": 3600
        }),
    ] {
        let (status, _) = app
            .send_request(Method::POST, "/zones", Some(invalid_rname))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let create_zone_request = json!({
        "name": format!(" {}. ", zone_name.to_ascii_uppercase()),
        "mname": format!("NS1.{}.", zone_name.to_ascii_uppercase()),
        "rname": "Host.Master@Example.Com.",
        "default_ttl": 3600
    });
    let (status, body) = app
        .send_request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["name"], zone_name);
    assert_eq!(body["zone"]["mname"], format!("ns1.{zone_name}"));
    // Only the domain part of the email is case-normalized; the local part is
    // case-significant and must be preserved.
    assert_eq!(body["zone"]["rname"], "Host.Master@example.com");

    let duplicate_zone_request = json!({
        "name": format!("{zone_name}."),
        "mname": format!("ns2.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600
    });
    let (status, _) = app
        .send_request(Method::POST, "/zones", Some(duplicate_zone_request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let second_zone = json!({
        "name": second_zone_name,
        "mname": format!("ns1.{second_zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600
    });
    let (status, _) = app
        .send_request(Method::POST, "/zones", Some(second_zone))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let normalize_update = json!({
        "name": format!(" {}. ", zone_name.to_ascii_uppercase()),
        "mname": format!("NS1.{}.", zone_name.to_ascii_uppercase()),
        "rname": "Host.Master@Example.Com.",
        "default_ttl": 7200
    });
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(normalize_update),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], zone_name);
    assert_eq!(body["zone"]["mname"], format!("ns1.{zone_name}"));
    assert_eq!(body["zone"]["rname"], "Host.Master@example.com");

    let rename_onto_existing = json!({
        "name": format!("{}.", second_zone_name.to_ascii_uppercase()),
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600
    });
    let (status, _) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(rename_onto_existing),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    for invalid_update in [
        json!({
            "name": format!("{}..example.com", app.namespace()),
            "mname": format!("ns1.{zone_name}"),
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": zone_name,
            "mname": format!("ns1.{zone_name}"),
            "rname": "hostmaster@example.com",
            "default_ttl": 0
        }),
    ] {
        let (status, _) = app
            .send_request(
                Method::PUT,
                &format!("/zones/{zone_name}"),
                Some(invalid_update),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

/// Verify rejection of invalid zone names and TTLs.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_reject_invalid_name_and_ttl() {
    let app = TestApp::start().await;

    for invalid_zone in [
        json!({
            "name": "*.example.com",
            "mname": "ns1.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": ".",
            "mname": "ns.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "_tcp.example.com",
            "mname": "ns._tcp.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "test..example.com",
            "mname": "ns.test.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "-test.example.com",
            "mname": "ns.-test.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "low-ttl.example.com",
            "mname": "ns.low-ttl.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 0
        }),
        json!({
            "name": "high-ttl.example.com",
            "mname": "ns.high-ttl.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 604801
        }),
    ] {
        let (status, _) = app
            .send_request(Method::POST, "/zones", Some(invalid_zone))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // These look suspicious but are legal: an mname outside the zone
    // (out-of-bailiwick) and an NS name unrelated to the zone.
    for valid_zone in [
        json!({
            "name": app.zone_name("bailiwick.example.com"),
            "mname": "ns.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": app.zone_name("bad-ns.example.com"),
            "mname": "badtest.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
    ] {
        let (status, _) = app
            .send_request(Method::POST, "/zones", Some(valid_zone))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
}

/// Verify that `zone_status` reports secondaries.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_status_reports_secondaries() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/status"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"], zone_name);
    assert_eq!(
        body["serial"].as_i64().unwrap(),
        zone["serial"].as_i64().unwrap()
    );

    let secondaries = body["secondaries"].as_array().expect("missing secondaries");
    if app.has_dns_secondaries() {
        // Compose mode: both BIND9 secondaries must converge to in_sync.
        assert_eq!(secondaries.len(), 2);
        let mut attempts = 0;
        loop {
            let (_, body) = app
                .send_request(Method::GET, &format!("/zones/{zone_name}/status"), None)
                .await;
            let all_in_sync = body["secondaries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["status"] == "in_sync");
            if all_in_sync {
                break;
            }
            attempts += 1;
            assert!(attempts < 60, "secondaries never reached in_sync: {body}");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    } else {
        // Local mode has no secondaries configured.
        assert!(secondaries.is_empty());
    }

    let missing_zone = app.zone_name("missing.example");
    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{missing_zone}/status"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ZONE_NOT_FOUND");
}

/// Verify that a disabled zone stops answering DNS while remaining editable through the API.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_disabled_zone_leaves_the_dns_plane_but_stays_editable() {
    // The transfer ACL must admit the test's own loopback AXFR.
    let app = TestApp::start_with_options(TestAppOptions {
        secondary_addrs: "127.0.0.1".to_string(),
        ..Default::default()
    })
    .await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let server = format!("127.0.0.1:{}", app.dns_port());
    assert!(
        probe_zone_soa(app.dns_port(), zone_name),
        "a served zone answers its SOA"
    );

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(json!({ "enabled": false, "description": "paused for migration" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["zone"]["enabled"], false, "{body}");
    assert_eq!(
        body["zone"]["description"], "paused for migration",
        "{body}"
    );

    // Unknown to the DNS plane, so a secondary drops the zone instead of
    // serving a copy nothing refreshes.
    assert!(
        !probe_zone_soa(app.dns_port(), zone_name),
        "a disabled zone must not answer its SOA"
    );
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "from_server": server, "mode": "replace" })),
        )
        .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a disabled zone must refuse the transfer: {body}"
    );

    // The management plane still holds it: listable under the filter, and
    // editable.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/zones?enabled=false&search={zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|zone| zone["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, [zone_name], "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www", "type": "A", "value": "192.0.2.31",
                "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(json!({ "enabled": true, "description": "" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["zone"]["description"].is_null(), "{body}");
    assert!(
        probe_zone_soa(app.dns_port(), zone_name),
        "re-enabling serves the zone again"
    );
}
