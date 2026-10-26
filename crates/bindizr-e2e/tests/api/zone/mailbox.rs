//! Restore accepted SOA mailbox domains through export, import and history.

use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Preserve accepted domain octets when importing an export and restoring a stored version.
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
    .iter()
    .enumerate()
    {
        let name = app.zone_name(&format!("mailbox-{index}.example"));
        let rname = format!("first.last@{domain}");

        let (status, created) = app
            .send_request(
                Method::POST,
                "/zones",
                Some(json!({
                    "name": name, "mname": "ns.example.com", "rname": rname, "serial": 1
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["zone"]["rname"], rname);

        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "zone_name": name, "name": "www", "type": "A", "value": "192.0.2.1"
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(app.read_zone_serial(&name).await, 2);

        let (status, exported) = app
            .send_request(Method::GET, &format!("/zones/{name}/export"), None)
            .await;

        assert_eq!(status, StatusCode::OK, "{exported}");
        let imported_name = app.zone_name(&format!("imported-{index}.example"));
        let content = exported
            .as_str()
            .unwrap()
            .replace(&format!("{name}."), &format!("{imported_name}."));

        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("/zones/{imported_name}/import"),
                Some(json!({"content": content, "create": true})),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{rname}: {body}");

        let (status, imported) = app
            .send_request(Method::GET, &format!("/zones/{imported_name}"), None)
            .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(imported["zone"]["rname"], rname);

        for dry_run in [true, false] {
            let (status, body) = app
                .send_request(
                    Method::POST,
                    &format!("/zones/{name}/versions/1/rollback?dry_run={dry_run}"),
                    None,
                )
                .await;

            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(
                app.read_zone_serial(&name).await,
                if dry_run {
                    2
                } else {
                    3
                }
            );
        }

        let (status, restored) = app
            .send_request(Method::GET, &format!("/zones/{name}"), None)
            .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(restored["zone"]["rname"], rname);
        assert!(
            app.list_records(&name)
                .await
                .iter()
                .all(|record| record["type"] != "A")
        );
    }
}
