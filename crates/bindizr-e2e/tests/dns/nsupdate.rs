use domain::base::{Rtype, iana::Rcode};
use serial_test::serial;

use crate::common::{
    TestApp, TestAppOptions,
    nsupdate::{PrereqRr, UpdateRr, send_update},
};

/// These drive bindizr's own DNS listener over UDP with unsigned updates, so
/// the whole RFC 2136 path runs: message decoding, prerequisites, the apply
/// transaction, and the serial bump. TSIG has its own unit coverage.
async fn unsigned_nsupdate_app() -> TestApp {
    TestApp::start_with_options(TestAppOptions {
        nsupdate_allow_unsigned: true,
        ..TestAppOptions::default()
    })
    .await
}

#[tokio::test]
#[serial]
async fn nsupdate_adds_and_deletes_records() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let owner = format!("www.{zone_name}.");
    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRr::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.10".to_string(),
        }],
    )
    .expect("add update");
    assert_eq!(rcode, Rcode::NOERROR);

    let records = app.list_records(&zone_name).await;
    assert!(
        records
            .iter()
            .any(|record| record["name"] == format!("www.{zone_name}.")
                && record["record_type"] == "A"
                && record["value"] == "192.0.2.10"),
        "record was not added: {records:#?}"
    );

    // A second identical add is a silent no-op (RFC 2136, Section 3.4.2.2).
    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRr::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.10".to_string(),
        }],
    )
    .expect("duplicate add");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.list_records(&zone_name).await.len(), records.len());

    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRr::DeleteA {
            name: owner.clone(),
            addr: "192.0.2.10".to_string(),
        }],
    )
    .expect("delete update");
    assert_eq!(rcode, Rcode::NOERROR);

    assert!(
        !app.list_records(&zone_name)
            .await
            .iter()
            .any(|record| record["value"] == "192.0.2.10"),
        "record was not deleted"
    );
}

#[tokio::test]
#[serial]
async fn nsupdate_deletes_a_whole_rrset() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-rrset.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let owner = format!("multi.{zone_name}.");
    for addr in ["192.0.2.20", "192.0.2.21"] {
        send_update(
            port,
            &zone_name,
            &[],
            &[UpdateRr::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: addr.to_string(),
            }],
        )
        .expect("add update");
    }

    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRr::DeleteRrset {
            name: owner.clone(),
            rtype: Rtype::A,
        }],
    )
    .expect("rrset delete");
    assert_eq!(rcode, Rcode::NOERROR);

    assert!(
        !app.list_records(&zone_name)
            .await
            .iter()
            .any(|record| record["name"] == format!("multi.{zone_name}.")),
        "RRset was not deleted"
    );
}

#[tokio::test]
#[serial]
async fn nsupdate_applies_nothing_when_a_prerequisite_fails() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-prereq.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let before = app.list_records(&zone_name).await.len();
    let owner = format!("guarded.{zone_name}.");

    // The owner does not exist, so a "must exist" prerequisite fails.
    let rcode = send_update(
        port,
        &zone_name,
        &[PrereqRr::NameInUse {
            name: owner.clone(),
        }],
        &[UpdateRr::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.30".to_string(),
        }],
    )
    .expect("failing prerequisite");
    assert_eq!(rcode, Rcode::NXDOMAIN);
    assert_eq!(app.list_records(&zone_name).await.len(), before);

    // The matching "must not exist" prerequisite lets the same update through.
    let rcode = send_update(
        port,
        &zone_name,
        &[PrereqRr::NameNotInUse {
            name: owner.clone(),
        }],
        &[UpdateRr::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.30".to_string(),
        }],
    )
    .expect("passing prerequisite");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.list_records(&zone_name).await.len(), before + 1);
}

#[tokio::test]
#[serial]
async fn nsupdate_refuses_an_owner_outside_the_zone() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-notzone.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let rcode = send_update(
        app.dns_port(),
        &zone_name,
        &[],
        &[UpdateRr::AddA {
            name: "www.elsewhere.example.".to_string(),
            ttl: 300,
            addr: "192.0.2.40".to_string(),
        }],
    )
    .expect("out-of-zone update");

    assert_eq!(rcode, Rcode::NOTZONE);
}

#[tokio::test]
#[serial]
async fn nsupdate_advances_the_zone_serial_once_per_message() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-serial.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let before = app.zone_serial(&zone_name).await;

    let owner = format!("pair.{zone_name}.");
    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[
            UpdateRr::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: "192.0.2.50".to_string(),
            },
            UpdateRr::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: "192.0.2.51".to_string(),
            },
        ],
    )
    .expect("two-record update");
    assert_eq!(rcode, Rcode::NOERROR);

    assert_eq!(app.zone_serial(&zone_name).await, before + 1);

    // An update that changes nothing must leave the serial alone, or every
    // no-op would make secondaries re-transfer.
    let rcode = send_update(
        port,
        &zone_name,
        &[],
        &[UpdateRr::DeleteA {
            name: owner,
            addr: "198.51.100.1".to_string(),
        }],
    )
    .expect("no-op update");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.zone_serial(&zone_name).await, before + 1);
}
