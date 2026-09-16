use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify that zone import accepts every user type and round-trips the export.
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
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"]["added"], 5);
    assert_eq!(body["errors"].as_array().unwrap().len(), 0, "{body}");

    let (_, body) = app
        .send_request(
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
        .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let exported = body.as_str().unwrap().to_string();

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": exported })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"]["added"], 0, "{body}");
    assert_eq!(body["errors"].as_array().unwrap().len(), 0, "{body}");

    // The delegation NS cannot go while its DS survives; DS first, then NS.
    let record_id = |listing: &serde_json::Value| listing["items"][0]["id"].as_i64().unwrap();
    let (_, ns_listing) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=NS&name=sub"),
            None,
        )
        .await;
    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records/{}", record_id(&ns_listing)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (_, ds_listing) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=DS&name=sub"),
            None,
        )
        .await;
    for listing in [ds_listing, ns_listing] {
        let (status, _) = app
            .send_request(
                Method::DELETE,
                &format!("/records/{}", record_id(&listing)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }
}

/// Verify that DNAME and NAPTR survive an import and export round trip.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dname_and_naptr_survive_an_import_and_export_round_trip() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let content = concat!(
        "tel IN NAPTR 200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" .\n",
        "sip IN NAPTR 100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com.\n",
        "alias IN DNAME target.example.com.\n",
    );
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true, "{body}");
    assert_eq!(body["summary"]["added"], 3, "{body}");

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // The rdata comes back as written, the root replacement included.
    let exported = body.as_str().expect("zone file text");
    assert!(
        exported.contains("200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" ."),
        "{exported}"
    );
    assert!(
        exported.contains("100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com."),
        "{exported}"
    );
    assert!(
        exported.contains("DNAME\ttarget.example.com."),
        "{exported}"
    );
}

/// Verify that escaped labels and values survive an import and export round trip.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn escaped_labels_and_values_survive_an_import_and_export_round_trip() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let content = concat!(
        "0/25 IN NS    ns.example.com.\n",
        "1    IN CNAME 1.0/25.2.0.192.in-addr.arpa.\n",
        "@    IN CAA   0 issue \"a\\\"b\\\\c\"\n",
    );
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true, "{body}");
    assert_eq!(body["summary"]["added"], 3, "{body}");

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // RFC 2317, Section 4 delegates through a label carrying a slash, and the
    // CAA value keeps the escapes it was written with.
    let exported = body.as_str().expect("zone file text");
    assert!(
        exported.contains("1.0/25.2.0.192.in-addr.arpa."),
        "{exported}"
    );
    assert!(exported.contains(r#"0 issue "a\"b\\c""#), "{exported}");
}
