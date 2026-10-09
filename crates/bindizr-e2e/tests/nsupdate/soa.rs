//! SOA replacement follows RFC 2136, Sections 3.4.2.2 and 3.6.

use domain::base::Name;
use reqwest::{Method, StatusCode};
use serde_json::json;

use super::{
    common::{exported_record_sets, unsigned_nsupdate_app},
    *,
};

/// Build a replacement whose metadata differs from the default zone SOA.
fn replacement(zone: &str, serial: u32) -> Soa<Name<Vec<u8>>> {
    Soa::new(
        parse_name(&format!("ns2.{zone}")).unwrap(),
        parse_name(r"host\.master.example.net").unwrap(),
        Serial::from(serial),
        Ttl::from_secs(1800),
        Ttl::from_secs(900),
        Ttl::from_secs(86400),
        Ttl::from_secs(600),
    )
}

/// Read zone metadata through the API.
async fn metadata(app: &TestApp, zone: &str) -> Value {
    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["zone"].clone()
}

/// Ignore equal, older, and non-apex SOAs without changing records or metadata.
#[tokio::test]
#[serial]
async fn soa_ineffective_additions_are_successful_noops() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let before = metadata(&app, zone_name).await;
    let serial = u32::try_from(app.read_zone_serial(zone_name).await).unwrap();
    let records = app.list_records(zone_name).await;
    for (name, serial) in [
        (format!("{zone_name}."), serial),
        (format!("{zone_name}."), serial - 1),
        (format!("child.{zone_name}."), serial + 1),
        (format!("{zone_name}."), serial.wrapping_add(1 << 31)),
        (format!("{zone_name}."), u32::MAX),
    ] {
        let rcode = send_update(
            app.dns_port(),
            zone_name,
            &[],
            &[UpdateRecord::AddSoa {
                name,
                ttl: 600,
                soa: replacement(zone_name, serial),
            }],
        )
        .unwrap();
        assert_eq!(rcode, Rcode::NOERROR, "serial {serial}");
        assert_eq!(metadata(&app, zone_name).await, before);
        assert_eq!(app.list_records(zone_name).await, records);
    }
}

/// Keep the last advancing SOA and journal every record under that serial.
#[tokio::test]
#[serial]
async fn soa_replacement_versions_the_whole_update_once() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let serial = u32::try_from(zone["serial"].as_u64().unwrap()).unwrap();
    let add = |label: &str| UpdateRecord::AddA {
        name: format!("{label}.{zone_name}."),
        ttl: 300,
        addr: "192.0.2.150".to_string(),
    };
    let soa = |serial, ttl| UpdateRecord::AddSoa {
        name: format!("{zone_name}."),
        ttl,
        soa: replacement(zone_name, serial),
    };
    assert_eq!(
        send_update(
            app.dns_port(),
            zone_name,
            &[],
            &[
                add("before"),
                soa(serial + 10, 600),
                add("middle"),
                soa(serial + 20, 900),
                soa(serial + 15, 1200),
                soa(serial + 20, 1800),
                add("after"),
            ]
        )
        .unwrap(),
        Rcode::NOERROR,
    );
    let after = metadata(&app, zone_name).await;
    assert_eq!(after["serial"], serial + 20);
    assert_eq!(after["mname"], format!("ns2.{zone_name}"));
    assert_eq!(after["rname"], "host.master@example.net");
    assert_eq!(after["default_ttl"], 900);
    assert_eq!(after["refresh"], 1800);
    assert_eq!(after["retry"], 900);
    assert_eq!(after["expire"], 86400);
    assert_eq!(after["minimum_ttl"], 600);
    let (status, history) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/versions"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    assert_eq!(history["items"].as_array().unwrap().len(), 2);
    assert_eq!(history["items"][0]["serial"], serial + 20);
    assert_eq!(history["items"][0]["change_source"], "nsupdate");
    for (version, count, mname) in [(serial, 0, "ns1"), (serial + 20, 3, "ns2")] {
        let (status, detail) = app
            .send_request(
                Method::GET,
                &format!("/zones/{zone_name}/versions/{version}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(detail["version"]["mname"], format!("{mname}.{zone_name}"));
        assert_eq!(
            detail["records"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["type"] == "A")
                .count(),
            count
        );
    }
    let prerequisite = PrereqRecord::SoaEquals {
        name: format!("{zone_name}."),
        soa: replacement(zone_name, serial + 20),
    };
    assert_eq!(
        send_update(app.dns_port(), zone_name, &[prerequisite], &[add("next")]).unwrap(),
        Rcode::NOERROR
    );
    assert_eq!(
        app.read_zone_serial(zone_name).await,
        i64::from(serial + 21)
    );
    let (status, rollback) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/versions/{serial}/rollback"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{rollback}");
    let restored = metadata(&app, zone_name).await;
    for field in [
        "mname",
        "rname",
        "default_ttl",
        "refresh",
        "retry",
        "expire",
        "minimum_ttl",
    ] {
        assert_eq!(restored[field], zone[field], "{field}");
    }
    assert!(
        app.list_records(zone_name)
            .await
            .iter()
            .all(|r| r["type"] != "A")
    );
}

/// Require zone:update for SOA changes and preserve TCP response authentication.
#[tokio::test]
#[serial]
async fn soa_replacement_uses_zone_permissions() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "soa-writer", KeyRole::Own).await;
    app.run_cli_success(&[
        "role",
        "grant",
        "soa-writer",
        "--zone",
        zone_name,
        "--actions",
        "record:create",
    ])
    .await;
    let before = metadata(&app, zone_name).await;
    let updates = [UpdateRecord::AddSoa {
        name: format!("{zone_name}."),
        ttl: 600,
        soa: replacement(zone_name, 100),
    }];
    assert_eq!(
        send_signed_update_tcp(app.dns_port(), zone_name, &[], &updates, &key).unwrap(),
        Rcode::REFUSED
    );
    assert_eq!(metadata(&app, zone_name).await, before);
    app.run_cli_success(&[
        "role",
        "grant",
        "soa-writer",
        "--zone",
        zone_name,
        "--actions",
        "zone:update",
    ])
    .await;
    assert_eq!(
        send_signed_update_tcp(app.dns_port(), zone_name, &[], &updates, &key).unwrap(),
        Rcode::NOERROR
    );
    assert_eq!(app.read_zone_serial(zone_name).await, 100);
}

/// Policy failures and failed prerequisites roll back SOA and ordinary records together.
#[tokio::test]
#[serial]
async fn soa_replacement_refusals_are_atomic() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    assert_eq!(
        send_update(
            app.dns_port(),
            zone_name,
            &[],
            &[UpdateRecord::AddDname {
                name: format!("blocked.{zone_name}."),
                ttl: 300,
                target: "target.example.net.".to_string(),
            }]
        )
        .unwrap(),
        Rcode::NOERROR
    );
    let before = metadata(&app, zone_name).await;
    let records = app.list_records(zone_name).await;
    for (ttl, soa) in [
        (600, replacement(zone_name, i32::MAX as u32 + 1)),
        (30, replacement(zone_name, 100)),
        (
            600,
            Soa::new(
                parse_name("ns.example.net").unwrap(),
                parse_name(".").unwrap(),
                Serial::from(100),
                Ttl::from_secs(100),
                Ttl::from_secs(100),
                Ttl::from_secs(100),
                Ttl::from_secs(100),
            ),
        ),
        (
            600,
            Soa::new(
                parse_name("ns.example.net").unwrap(),
                parse_name("admin.example.net").unwrap(),
                Serial::from(100),
                Ttl::from_secs(u32::MAX),
                Ttl::from_secs(100),
                Ttl::from_secs(100),
                Ttl::from_secs(100),
            ),
        ),
    ] {
        let updates = [
            UpdateRecord::AddA {
                name: format!("atomic.{zone_name}."),
                ttl: 300,
                addr: "192.0.2.151".to_string(),
            },
            UpdateRecord::AddSoa {
                name: format!("{zone_name}."),
                ttl: 600,
                soa: replacement(zone_name, 20),
            },
            UpdateRecord::AddSoa {
                name: format!("{zone_name}."),
                ttl,
                soa,
            },
        ];
        assert_eq!(
            send_update(app.dns_port(), zone_name, &[], &updates).unwrap(),
            Rcode::REFUSED
        );
        assert_eq!(metadata(&app, zone_name).await, before);
        assert_eq!(app.list_records(zone_name).await, records);
    }
    let prerequisites = [PrereqRecord::NameInUse {
        name: format!("absent.{zone_name}."),
    }];
    let updates = [UpdateRecord::AddSoa {
        name: format!("{zone_name}."),
        ttl: 600,
        soa: replacement(zone_name, 100),
    }];
    assert_eq!(
        send_update(app.dns_port(), zone_name, &prerequisites, &updates).unwrap(),
        Rcode::NXDOMAIN
    );
    assert_eq!(metadata(&app, zone_name).await, before);

    // A record conflict after an earlier write must roll back its journal too.
    let updates = [
        UpdateRecord::AddA {
            name: format!("written-first.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.152".to_string(),
        },
        UpdateRecord::AddSoa {
            name: format!("{zone_name}."),
            ttl: 600,
            soa: replacement(zone_name, 100),
        },
        UpdateRecord::AddA {
            name: format!("child.blocked.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.153".to_string(),
        },
    ];
    assert_eq!(
        send_update(app.dns_port(), zone_name, &[], &updates).unwrap(),
        Rcode::REFUSED
    );
    assert_eq!(metadata(&app, zone_name).await, before);
    assert_eq!(app.list_records(zone_name).await, records);
    let (status, history) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/versions"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    assert_eq!(history["items"].as_array().unwrap().len(), 2);
}

/// An explicit advance to the stored ceiling still permits subsequent SOA no-ops.
#[tokio::test]
#[serial]
async fn soa_noops_do_not_require_serial_headroom() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    for serial in [i32::MAX as u32, i32::MAX as u32, i32::MAX as u32 - 1] {
        assert_eq!(
            send_update(
                app.dns_port(),
                zone_name,
                &[],
                &[UpdateRecord::AddSoa {
                    name: format!("{zone_name}."),
                    ttl: 600,
                    soa: replacement(zone_name, serial)
                }]
            )
            .unwrap(),
            Rcode::NOERROR
        );
        assert_eq!(app.read_zone_serial(zone_name).await, i64::from(i32::MAX));
    }
}

/// Re-sign the updated SOA and use it in subsequent value-dependent prerequisites.
#[tokio::test]
#[serial]
async fn soa_replacement_updates_the_signed_zone() {
    use domain::{base::rdata::ComposeRecordData, dep::octseq::parse::Parser, rdata::Rrsig};

    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({"parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let before = exported_record_sets(&app, zone_name).await;
    let soa = replacement(zone_name, 100);
    assert_eq!(
        send_update(
            app.dns_port(),
            zone_name,
            &[],
            &[UpdateRecord::AddSoa {
                name: format!("{zone_name}."),
                ttl: 900,
                soa: soa.clone()
            }]
        )
        .unwrap(),
        Rcode::NOERROR
    );
    let after = exported_record_sets(&app, zone_name).await;
    let key = (format!("{zone_name}."), Rtype::SOA);
    let mut expected = Vec::new();
    soa.compose_rdata(&mut expected).unwrap();
    assert_eq!(after[&key], [expected]);
    let key = (format!("{zone_name}."), Rtype::RRSIG);
    assert_ne!(after[&key], before[&key]);
    let signatures: Vec<_> = after[&key]
        .iter()
        .map(|data| Rrsig::parse(&mut Parser::from_ref(data)).unwrap())
        .filter(|sig| sig.type_covered() == Rtype::SOA)
        .collect();
    assert!(!signatures.is_empty());
    assert!(
        signatures
            .iter()
            .all(|sig| sig.original_ttl() == Ttl::from_secs(900))
    );
    let prerequisites = [PrereqRecord::SoaEquals {
        name: format!("{zone_name}."),
        soa,
    }];
    assert_eq!(
        send_update(app.dns_port(), zone_name, &prerequisites, &[]).unwrap(),
        Rcode::NOERROR
    );
    assert_eq!(app.read_zone_serial(zone_name).await, 100);
}

/// Transfer the old and new SOAs around one delta even when the serial skips values.
#[tokio::test]
#[serial]
async fn soa_replacement_is_replayed_by_ixfr() {
    use domain::base::{Message, MessageBuilder, iana::Class, rdata::ComposeRecordData};

    let app = unsigned_nsupdate_app().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    // Keep the journal smaller than the zone so the server selects IXFR.
    let padding: Vec<_> = (0..20)
        .map(|i| UpdateRecord::AddA {
            name: format!("padding{i}.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.160".to_string(),
        })
        .collect();
    assert_eq!(
        send_update(app.dns_port(), zone_name, &[], &padding).unwrap(),
        Rcode::NOERROR
    );
    let old_serial = u32::try_from(app.read_zone_serial(zone_name).await).unwrap();
    let before = exported_record_sets(&app, zone_name).await;
    let soa = replacement(zone_name, old_serial + 10);
    assert_eq!(
        send_update(
            app.dns_port(),
            zone_name,
            &[],
            &[
                UpdateRecord::AddSoa {
                    name: format!("{zone_name}."),
                    ttl: 600,
                    soa: soa.clone()
                },
                UpdateRecord::AddA {
                    name: format!("delta.{zone_name}."),
                    ttl: 300,
                    addr: "192.0.2.161".to_string()
                },
            ]
        )
        .unwrap(),
        Rcode::NOERROR
    );
    let name = parse_name(zone_name).unwrap();
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(0x1234);
    let mut question = builder.question();
    question.push((&name, Rtype::IXFR, Class::IN)).unwrap();
    let mut authority = question.authority();
    authority
        .push((
            &name,
            Class::IN,
            Ttl::ZERO,
            replacement(zone_name, old_serial),
        ))
        .unwrap();
    let response = crate::common::exchange_tcp(app.dns_port(), &authority.finish()).unwrap();
    let message = Message::from_octets(response).unwrap();
    assert_eq!(message.header().rcode(), Rcode::NOERROR);
    let answers: Vec<_> = message.answer().unwrap().map(Result::unwrap).collect();
    assert_eq!(answers.len(), 5, "IXFR must not fall back to AXFR");
    let mut new_rdata = Vec::new();
    soa.compose_rdata(&mut new_rdata).unwrap();
    let old_rdata = &before[&(format!("{zone_name}."), Rtype::SOA)][0];
    for (index, ttl, expected) in [
        (0, 600, &new_rdata),
        (1, 3600, old_rdata),
        (2, 600, &new_rdata),
        (4, 600, &new_rdata),
    ] {
        let record = answers[index].to_record::<Soa<_>>().unwrap().unwrap();
        assert_eq!(record.ttl(), Ttl::from_secs(ttl));
        let mut data = Vec::new();
        record.data().compose_rdata(&mut data).unwrap();
        assert_eq!(&data, expected);
    }
    assert_eq!(answers[3].rtype(), Rtype::A);
    assert_eq!(answers[3].owner().to_string(), format!("delta.{zone_name}"));
}
