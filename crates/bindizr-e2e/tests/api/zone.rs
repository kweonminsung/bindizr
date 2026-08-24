use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::common::TestApp;

/// Seed records directly in the DB via the bulk endpoint.
async fn seed_records(app: &TestApp, zone_name: &str, records: Value) {
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/records/bulk"),
            Some(json!({ "records": records })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

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
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let created_zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(created_zone_name, zone_name);

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{created_zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], zone_name);

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
        .request(
            Method::PUT,
            &format!("/zones/{created_zone_name}"),
            Some(update_zone_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let actual_updated_zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(actual_updated_zone_name, updated_zone_name);

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/zones/{actual_updated_zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(
            Method::GET,
            &format!("/zones/{actual_updated_zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

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
            .request(Method::POST, "/zones", Some(invalid_rname))
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
        .request(Method::POST, "/zones", Some(create_zone_request))
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
        .request(Method::POST, "/zones", Some(duplicate_zone_request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let second_zone = json!({
        "name": second_zone_name,
        "mname": format!("ns1.{second_zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600
    });
    let (status, _) = app.request(Method::POST, "/zones", Some(second_zone)).await;
    assert_eq!(status, StatusCode::CREATED);

    let normalize_update = json!({
        "name": format!(" {}. ", zone_name.to_ascii_uppercase()),
        "mname": format!("NS1.{}.", zone_name.to_ascii_uppercase()),
        "rname": "Host.Master@Example.Com.",
        "default_ttl": 7200
    });
    let (status, body) = app
        .request(
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
        .request(
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
            .request(
                Method::PUT,
                &format!("/zones/{zone_name}"),
                Some(invalid_update),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

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
            .request(Method::POST, "/zones", Some(invalid_zone))
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
        let (status, _) = app.request(Method::POST, "/zones", Some(valid_zone)).await;
        assert_eq!(status, StatusCode::CREATED);
    }
}

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
    let (status, body) = app.request(Method::POST, "/zones", Some(seeded_zone)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["serial"], 2026072501i64);

    let update_zone_request = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 7200
    });
    let (status, body) = app
        .request(
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
            .request(Method::POST, "/zones", Some(out_of_range_zone))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_dry_run_then_apply() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let content = "www IN A 192.0.2.10\nmail IN A 192.0.2.11\nftp IN CNAME www\n";

    // Dry run: reports the plan without applying it.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "dryRun": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["summary"]["added"], 3);
    assert_eq!(body["errors"].as_array().unwrap().len(), 0);

    // Nothing applied yet.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    let before = body["items"].as_array().unwrap().len();

    // Real apply.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 3);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), before + 3);

    // Re-applying in append mode is idempotent: everything is unchanged.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 0);
    assert_eq!(body["summary"]["unchanged"], 3);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_accepts_every_user_type_and_round_trips_the_export() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The DS line precedes its delegation NS on purpose: exports sort DS
    // before NS at one owner, so import must not validate in file order.
    let content = concat!(
        "sub IN DS 12345 13 2 abababababababababababababababababababababababababababababababab\n",
        "sub IN NS ns1.example.net.\n",
        "@ IN CAA 0 issue \"letsencrypt.org\"\n",
        "ssh IN SSHFP 4 2 abababababababababababababababababababababababababababababababab\n",
        "_443._tcp IN TLSA 3 1 1 abababababababababababababababababababababababababababababababab\n",
    );

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"]["added"], 5);
    assert_eq!(body["errors"].as_array().unwrap().len(), 0, "{body}");

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=SSHFP"),
            None,
        )
        .await;
    assert_eq!(
        body["items"][0]["value"],
        format!(
            "4 2 {}",
            "abababababababababababababababababababababababababababababababab".to_uppercase()
        )
    );

    // The unsigned export must re-import as all-unchanged.
    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let exported = body.as_str().unwrap().to_string();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": exported })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"]["added"], 0, "{body}");
    assert_eq!(body["errors"].as_array().unwrap().len(), 0, "{body}");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_replace_mode() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "keep", "record_type": "A", "value": "192.0.2.1" },
            { "name": "drop", "record_type": "A", "value": "192.0.2.2" }
        ]),
    )
    .await;

    // Replace: keep stays (same value), drop is removed, add is created.
    let content = "keep IN A 192.0.2.1\nadd IN A 192.0.2.3\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "mode": "replace" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 1);
    assert_eq!(body["summary"]["deleted"], 1);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=drop"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=add"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_upsert_mode_replaces_only_named_rrsets() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The three ways upsert must differ from replace, which would drop all of
    // these: a multi-record RRset, another type on that owner, another owner.
    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "www", "record_type": "A", "value": "192.0.2.1" },
            { "name": "www", "record_type": "A", "value": "192.0.2.2" },
            { "name": "www", "record_type": "TXT", "value": "keep me" },
            { "name": "other", "record_type": "A", "value": "192.0.2.9" }
        ]),
    )
    .await;

    // Only the `www` A RRset appears in the file, so only it is replaced.
    let content = "www IN A 192.0.2.3\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "mode": "upsert" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 1);
    assert_eq!(body["summary"]["deleted"], 2);

    let values = |body: &serde_json::Value| -> Vec<String> {
        let mut v: Vec<String> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["value"].as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    };

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www&record_type=A"),
            None,
        )
        .await;
    assert_eq!(values(&body), vec!["192.0.2.3"]);

    // Same owner, different type: untouched.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www&record_type=TXT"),
            None,
        )
        .await;
    assert_eq!(values(&body), vec!["keep me"]);

    // Different owner entirely: untouched.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=other"),
            None,
        )
        .await;
    assert_eq!(values(&body), vec!["192.0.2.9"]);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_reconciles_ttl() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "www", "record_type": "A", "value": "192.0.2.1", "ttl": 300 }
        ]),
    )
    .await;

    let ttl_of = |body: &serde_json::Value| -> i64 {
        body["items"].as_array().unwrap()[0]["ttl"]
            .as_i64()
            .unwrap()
    };

    // Upsert with only the TTL changed: reconciled in place, not left unchanged.
    let content = "www 600 IN A 192.0.2.1\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "mode": "upsert" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 0);
    assert_eq!(body["summary"]["deleted"], 0);
    assert_eq!(body["summary"]["updated"], 1);
    assert_eq!(body["summary"]["unchanged"], 0);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(ttl_of(&body), 600);

    // Re-importing the same TTL is idempotent: nothing to reconcile.
    let (_, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "mode": "upsert" })),
        )
        .await;
    assert_eq!(body["summary"]["updated"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    // Append never modifies already-present records, TTL included.
    let (_, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": "www 900 IN A 192.0.2.1\n", "mode": "append" })),
        )
        .await;
    assert_eq!(body["summary"]["updated"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(ttl_of(&body), 600);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_reports_validation_errors() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // A CNAME cannot coexist with another record of the same name.
    let content = "dup IN A 192.0.2.1\ndup IN CNAME www\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert!(!body["errors"].as_array().unwrap().is_empty());

    // Nothing applied because of the validation error.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=dup"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_preview_shows_empty_diff_on_validation_error() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // A CNAME that can't coexist with the A fails the whole import, so the dry-run
    // preview must report the error with an empty diff, not a never-applied add.
    let content = "dup IN A 192.0.2.1\ndup IN CNAME www\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "dry_run": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert_eq!(body["dry_run"], true);
    assert!(!body["errors"].as_array().unwrap().is_empty());
    assert!(
        body["diff"]["entries"].as_array().unwrap().is_empty(),
        "preview diff should be empty when the import has errors: {}",
        body["diff"]
    );
    assert_eq!(body["diff"]["summary"]["added"], 0);
}

// Append imports load only rows sharing an owner name with the file, so these
// check constraints against records that exist only in the DB.

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_append_rejects_cname_over_existing_db_record() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Seed an A record directly in the DB (stored under the lowercased name).
    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "www", "record_type": "A", "value": "192.0.2.1" }
        ]),
    )
    .await;

    // Append a CNAME for the same owner in a different case: the scoped load must
    // match the existing A case-insensitively, so CNAME exclusivity rejects it.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": "WWW IN CNAME target\n", "mode": "append" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert!(!body["errors"].as_array().unwrap().is_empty());

    // The original A is untouched and no CNAME was added.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["record_type"], "A");
    assert_eq!(items[0]["value"], "192.0.2.1");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_append_rejects_record_over_existing_cname() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "alias", "record_type": "CNAME", "value": "target.example.com." }
        ]),
    )
    .await;

    // Append an A for the same owner: CNAME exclusivity must reject it.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": "alias IN A 192.0.2.9\n", "mode": "append" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert!(!body["errors"].as_array().unwrap().is_empty());

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=alias"),
            None,
        )
        .await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["record_type"], "CNAME");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_append_dedups_against_existing_db_record() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "www", "record_type": "A", "value": "192.0.2.1" }
        ]),
    )
    .await;

    // Appending a record already present in the DB is a no-op, not a duplicate.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": "www IN A 192.0.2.1\n", "mode": "append" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_append_into_populated_zone_isolates_names() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Populate two unrelated names.
    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "a1", "record_type": "A", "value": "192.0.2.1" },
            { "name": "b1", "record_type": "A", "value": "192.0.2.2" }
        ]),
    )
    .await;

    // Appending a brand-new name adds only it; the existing names are untouched.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": "c1 IN A 192.0.2.3\n", "mode": "append" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 1);
    assert_eq!(body["summary"]["unchanged"], 0);

    for name in ["a1", "b1", "c1"] {
        let (_, body) = app
            .request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&name={name}"),
                None,
            )
            .await;
        assert_eq!(
            body["items"].as_array().unwrap().len(),
            1,
            "expected exactly one record for {name}"
        );
    }
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_versions_list_and_get() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let base_serial = zone["serial"].as_i64().unwrap();

    // serial +1: add record A; serial +2: add record B.
    let record_a = json!({
        "name": "www", "record_type": "A", "value": "192.0.2.50",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app.request(Method::POST, "/records", Some(record_a)).await;
    assert_eq!(status, StatusCode::CREATED);
    let record_b = json!({
        "name": "mail", "record_type": "A", "value": "192.0.2.51",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app.request(Method::POST, "/records", Some(record_b)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/versions"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("missing version items");
    assert!(items.len() >= 2);
    let serials: Vec<i64> = items
        .iter()
        .map(|item| item["serial"].as_i64().unwrap())
        .collect();
    assert!(
        serials.windows(2).all(|pair| pair[0] > pair[1]),
        "versions must be newest first: {serials:?}"
    );
    assert_eq!(serials[0], base_serial + 2);
    assert!(items[0]["rname"].as_str().unwrap().contains('@'));

    let (status, page) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/versions?limit=1&offset=1"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        page["items"][0]["serial"].as_i64().unwrap(),
        base_serial + 1
    );

    // At base_serial + 1 only record A existed.
    let (status, detail) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/versions/{}", base_serial + 1),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        detail["version"]["serial"].as_i64().unwrap(),
        base_serial + 1
    );
    let a_records: Vec<&str> = detail["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["record_type"] == "A")
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    assert_eq!(a_records, ["www"]);

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/versions/999999"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "VERSION_NOT_FOUND");

    let missing_zone = app.zone_name("missing.example");
    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones/{missing_zone}/versions"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ZONE_NOT_FOUND");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_rollback_dry_run_then_apply() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let keep_record = json!({
        "name": "keep", "record_type": "A", "value": "192.0.2.60",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(keep_record))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Capture the state to roll back to.
    let (_, zone_at_target) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    let target_serial = zone_at_target["zone"]["serial"].as_i64().unwrap();

    // Mutate past the target: add a record and change the SOA TTL.
    let extra_record = json!({
        "name": "extra", "record_type": "A", "value": "192.0.2.61",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(extra_record))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let soa_update = json!({
        "name": zone_name,
        "mname": zone["mname"].as_str().unwrap(),
        "rname": "changed@example.com",
        "default_ttl": 7200
    });
    let (status, _) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(soa_update),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (_, current) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    let current_serial = current["zone"]["serial"].as_i64().unwrap();

    // Dry run: nothing applied.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/rollback"),
            Some(json!({ "serial": target_serial, "dry_run": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["summary"]["soa_changed"], true);
    let (_, after_dry) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(
        after_dry["zone"]["serial"].as_i64().unwrap(),
        current_serial
    );
    assert_eq!(after_dry["zone"]["default_ttl"].as_i64().unwrap(), 7200);

    // Real rollback: state returns to target, serial advances.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/rollback"),
            Some(json!({ "serial": target_serial })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["target_serial"].as_i64().unwrap(), target_serial);
    assert_eq!(body["new_serial"].as_i64().unwrap(), current_serial + 1);

    let (_, restored) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(restored["zone"]["name"], zone_name);
    assert_eq!(
        restored["zone"]["serial"].as_i64().unwrap(),
        current_serial + 1
    );
    assert_eq!(restored["zone"]["default_ttl"].as_i64().unwrap(), 3600);
    assert_eq!(restored["zone"]["rname"], "admin@example.com");

    let (status, records) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = records["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 1);
    assert!(names[0].starts_with("keep."));
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_rollback_rejects_bad_serials() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let current_serial = zone["serial"].as_i64().unwrap();

    // Serials >= current and non-positive ones are invalid input; a serial in
    // the valid range that predates the first stored version is a 404.
    for (serial, expected_status, expected_code) in [
        (current_serial, StatusCode::BAD_REQUEST, "INVALID_INPUT"),
        (
            current_serial + 100,
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
        ),
        (0, StatusCode::BAD_REQUEST, "INVALID_INPUT"),
        (-5, StatusCode::BAD_REQUEST, "INVALID_INPUT"),
        (
            current_serial - 1,
            StatusCode::NOT_FOUND,
            "VERSION_NOT_FOUND",
        ),
    ] {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/zones/{zone_name}/rollback"),
                Some(json!({ "serial": serial })),
            )
            .await;
        assert_eq!(status, expected_status, "serial {serial}");
        assert_eq!(body["code"], expected_code, "serial {serial}");
    }
}

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
    let (status, body) = app.request(Method::POST, "/zones", Some(request)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["serial"].as_i64().unwrap(), 1);

    let record = json!({
        "name": "www", "record_type": "A", "value": "192.0.2.70",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app.request(Method::POST, "/records", Some(record)).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, after) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
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
        .request(
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

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_status_reports_secondaries() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/status"), None)
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
                .request(Method::GET, &format!("/zones/{zone_name}/status"), None)
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
        .request(Method::GET, &format!("/zones/{missing_zone}/status"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ZONE_NOT_FOUND");
}

// Both read the apex row's owner: the version returned it blank, and the
// update check compared the client spelling against the row form.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn apex_rows_render_and_update_through_their_presentation_name() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, detail) = app
        .request(
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
        .find(|record| record["record_type"] == "NS")
        .expect("apex NS row");
    for spelling in ["@", zone_name] {
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/records/{}", ns["id"].as_i64().unwrap()),
                Some(json!({
                    "name": spelling,
                    "record_type": "NS",
                    "value": ns["value"],
                    "default_ttl": 1200,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{spelling}: {body}");
    }
}
