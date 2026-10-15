//! DNS octets through management writes, imports and response round trips.

use domain::base::Rtype;
use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::{common::TestApp, nsupdate::common::exported_record_sets};

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
