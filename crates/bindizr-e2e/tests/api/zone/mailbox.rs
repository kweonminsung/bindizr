//! Restore accepted SOA mailbox domains through export, import and history.

use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify that accepted domain octets are preserved when importing an export and restoring a stored version.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn mailbox_domain_octets_survive_import_and_rollback() {
    let app = TestApp::start_local().await;

    for (index, domain) in [
        r"\255.example.com",
        r"\000.example.com",
        r"dot\046label.example",
        r"back\\slash.example",
        r"last\046",
        r"last\\",
    ]
    .into_iter()
    .enumerate()
    {
        let zone_name = app.zone_name(&format!("mailbox-{index}.example"));
        let rname = format!("first.last@{domain}");

        let (status, body) = app
            .send_request(
                Method::POST,
                "/zones",
                Some(json!({
                    "name": zone_name, "mname": "ns.example.com", "rname": rname, "serial": 1
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["zone"]["rname"], rname);

        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "zone_name": zone_name, "name": "www", "type": "A", "value": "192.0.2.1"
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(app.read_zone_serial(&zone_name).await, 2);

        let (status, body) = app
            .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        let imported_zone_name = app.zone_name(&format!("imported-{index}.example"));
        let content = body
            .as_str()
            .unwrap()
            .replace(&format!("{zone_name}."), &format!("{imported_zone_name}."));

        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("/zones/{imported_zone_name}/import"),
                Some(json!({ "content": content, "create": true })),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{rname}: {body}");

        let (status, body) = app
            .send_request(Method::GET, &format!("/zones/{imported_zone_name}"), None)
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["zone"]["rname"], rname);

        for dry_run in [true, false] {
            let (status, body) = app
                .send_request(
                    Method::POST,
                    &format!("/zones/{zone_name}/versions/1/rollback?dry_run={dry_run}"),
                    None,
                )
                .await;

            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(
                app.read_zone_serial(&zone_name).await,
                if dry_run {
                    2
                } else {
                    3
                }
            );
        }

        let (status, body) = app
            .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["zone"]["rname"], rname);
        assert!(
            app.list_records(&zone_name)
                .await
                .iter()
                .all(|record| record["type"] != "A")
        );
    }
}
