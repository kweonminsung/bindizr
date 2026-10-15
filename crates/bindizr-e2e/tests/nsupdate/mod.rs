pub(crate) mod common;
mod dnssec;
mod opaque;
mod soa;

use common::{exported_record_sets, unsigned_nsupdate_app};
use domain::{
    base::{
        Message, Rtype, Serial, Ttl,
        iana::{Class, Opcode, OptRcode, Rcode, TsigRcode},
    },
    rdata::{
        Soa,
        tsig::{Time48, Tsig},
    },
    tsig::ClientTransaction,
};
use serde_json::Value;
use serial_test::serial;

use crate::common::{
    TestApp,
    dns::{
        exchange_request, exchange_udp,
        nsupdate::{
            PrerequisiteRecord, UpdateRecord, build_update, send_signed_update_with_edns_version,
            send_signed_update_with_two_zones, send_update_tcp, send_update_udp,
        },
        parse_name,
        tsig::{KeyRole, create_tsig_key, verify_response_mac},
    },
    exchange_tcp,
};

/// Preserve CAA property octets through signed additions, prerequisites and deletions.
#[tokio::test]
#[serial]
async fn nsupdate_caa_values_keep_their_wire_bytes() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let owner = format!("caa.{zone_name}.");
    let key = create_tsig_key(&app, "caa-key", KeyRole::Admin).await;
    let values = [
        b"\x00\x05issue".to_vec(),
        b"\x00\x05ISSUE".to_vec(),
        b"\x01\x06custom".to_vec(),
        b"\x00\x09issuewild".to_vec(),
        b"\x80\x06custom".iter().copied().chain(0..=255u8).collect(),
        [vec![0, 255], vec![b'a'; 255], vec![b'b'; 300]].concat(),
    ];
    for rdata in &values {
        let additional = build_update(
            173,
            zone_name,
            Class::IN,
            &[],
            &[UpdateRecord::AddRecord {
                name: owner.clone(),
                rtype: Rtype::CAA,
                ttl: 300,
                rdata: rdata.clone(),
            }],
        )
        .unwrap();
        let response = exchange_request(additional, Some(&key), |message| {
            exchange_udp(app.dns_port(), message)
        })
        .unwrap();
        assert_eq!(
            response.header().rcode(),
            Rcode::NOERROR,
            "CAA RDATA {rdata:?}"
        );
    }
    let sets = exported_record_sets(&app, zone_name).await;
    let mut exported = sets.get(&(owner.clone(), Rtype::CAA)).unwrap().clone();
    let mut expected = values.to_vec();
    exported.sort();
    expected.sort();
    assert_eq!(exported, expected);

    for (index, rdata) in values.iter().enumerate() {
        let prerequisites: Vec<_> = values[index..]
            .iter()
            .map(|rdata| PrerequisiteRecord::RecordEquals {
                name: owner.clone(),
                rtype: Rtype::CAA,
                rdata: rdata.clone(),
            })
            .collect();
        let serial = app.read_zone_serial(zone_name).await;
        let rcode = send_update_udp(
            app.dns_port(),
            zone_name,
            &prerequisites,
            &[UpdateRecord::DeleteRecord {
                name: owner.clone(),
                rtype: Rtype::CAA,
                rdata: rdata.clone(),
            }],
            Some(&key),
        )
        .unwrap();
        assert_eq!(rcode, Rcode::NOERROR);
        assert_eq!(app.read_zone_serial(zone_name).await, serial + 1);
    }
    assert!(
        !exported_record_sets(&app, zone_name)
            .await
            .contains_key(&(owner, Rtype::CAA))
    );
}

/// Refuse invalid NAPTR flags without applying the update.
#[tokio::test]
#[serial]
async fn nsupdate_naptr_flags_refuse_the_whole_update() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "naptr-flags-key", KeyRole::Admin).await;
    for (flags, expected) in [
        (b"!".as_slice(), Rcode::REFUSED),
        (b"S-", Rcode::REFUSED),
        (b" ", Rcode::REFUSED),
        (b"\0", Rcode::REFUSED),
        ("é".as_bytes(), Rcode::REFUSED),
        (b"", Rcode::NOERROR),
        (b"uZ9", Rcode::NOERROR),
    ] {
        let before = app.list_records(zone_name).await;
        let serial = app.read_zone_serial(zone_name).await;
        // RFC 3403, Section 4.1: order, preference, three character-strings, replacement.
        let mut rdata = vec![0, 10, 0, 10, u8::try_from(flags.len()).unwrap()];
        rdata.extend_from_slice(flags);
        rdata.extend_from_slice(&[0, 0, 0]);
        let rcode = send_update_tcp(
            app.dns_port(),
            zone_name,
            &[],
            &[
                UpdateRecord::AddA {
                    name: format!("atomic.{zone_name}."),
                    ttl: 300,
                    addr: "192.0.2.19".to_string(),
                },
                UpdateRecord::AddRecord {
                    name: format!("naptr.{zone_name}."),
                    rtype: Rtype::NAPTR,
                    ttl: 300,
                    rdata: rdata.clone(),
                },
            ],
            Some(&key),
        )
        .unwrap();
        assert_eq!(rcode, expected, "flags {flags:?}");
        if expected == Rcode::REFUSED {
            assert_eq!(app.list_records(zone_name).await, before);
            assert_eq!(app.read_zone_serial(zone_name).await, serial);
        } else {
            assert_eq!(app.read_zone_serial(zone_name).await, serial + 1);
            let exported = exported_record_sets(&app, zone_name).await;
            assert!(exported[&(format!("naptr.{zone_name}."), Rtype::NAPTR)].contains(&rdata));
        }
    }
}

/// Refuse unserved zone classes before evaluating prerequisites or updates.
#[tokio::test]
#[serial]
async fn nsupdate_unserved_zone_classes_are_notauth_over_udp() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "class-udp-key", KeyRole::Admin).await;
    let before = app.list_records(zone_name).await;
    let serial = app.read_zone_serial(zone_name).await;
    let add = UpdateRecord::AddA {
        name: format!("class-check.{zone_name}."),
        ttl: 300,
        addr: "192.0.2.170".to_string(),
    };
    let cases = [
        (vec![], vec![]),
        (vec![], vec![add.clone()]),
        (
            vec![PrerequisiteRecord::NameInUse {
                name: format!("absent.{zone_name}."),
            }],
            vec![add.clone()],
        ),
        (
            vec![],
            vec![
                add.clone(),
                UpdateRecord::DeleteRecordSet {
                    name: "outside.example.net.".to_string(),
                    rtype: Rtype::AXFR,
                },
            ],
        ),
    ];
    for class in [
        Class::CH,
        Class::HS,
        Class::from_int(65280),
        Class::NONE,
        Class::ANY,
        Class::from_int(0),
        Class::from_int(u16::MAX),
    ] {
        for (prerequisites, updates) in &cases {
            for signing_key in [None, Some(&key)] {
                let mut request =
                    build_update(171, zone_name, class, prerequisites, updates).unwrap();
                request
                    .opt(|opt| {
                        opt.set_udp_payload_size(1232);
                        Ok(())
                    })
                    .unwrap();
                let response = exchange_request(request, signing_key, |message| {
                    exchange_udp(app.dns_port(), message)
                })
                .unwrap();
                assert_eq!(response.header().rcode(), Rcode::NOTAUTH, "class {class}");
                assert_eq!(response.header().opcode(), Opcode::UPDATE);
                let question = response.sole_question().unwrap();
                assert_eq!(question.qname().to_string(), zone_name);
                assert_eq!(question.qtype(), Rtype::SOA);
                assert_eq!(question.qclass(), class);
                assert_eq!(
                    response.opt().unwrap().rcode(response.header()),
                    OptRcode::NOTAUTH
                );
                assert_eq!(response.header_counts().ancount(), 0);
                assert_eq!(response.header_counts().nscount(), 0);
            }
        }
        assert_eq!(app.list_records(zone_name).await, before);
        assert_eq!(app.read_zone_serial(zone_name).await, serial);
    }
    assert_eq!(
        send_update_udp(app.dns_port(), zone_name, &[], &[add], None).unwrap(),
        Rcode::NOERROR
    );
    assert_eq!(app.read_zone_serial(zone_name).await, serial + 1);
}

/// Sign TCP class refusals and distinguish missing authority from missing grants.
#[tokio::test]
#[serial]
async fn nsupdate_zone_class_refusals_are_signed_over_tcp() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "class-tcp-key", KeyRole::Own).await;
    let before = app.list_records(zone_name).await;
    let serial = app.read_zone_serial(zone_name).await;
    let updates = [UpdateRecord::AddA {
        name: format!("must-not-exist.{zone_name}."),
        ttl: 300,
        addr: "192.0.2.171".to_string(),
    }];
    for (class, expected) in [
        (Class::IN, Rcode::REFUSED),
        (Class::CH, Rcode::NOTAUTH),
        (Class::HS, Rcode::NOTAUTH),
        (Class::from_int(65280), Rcode::NOTAUTH),
    ] {
        let request = build_update(172, zone_name, class, &[], &updates).unwrap();
        let response = exchange_request(request, Some(&key), |message| {
            exchange_tcp(app.dns_port(), message)
        })
        .unwrap();
        assert_eq!(response.header().id(), 172);
        assert_eq!(response.header().opcode(), Opcode::UPDATE);
        assert_eq!(response.header().rcode(), expected, "class {class}");
        assert_eq!(response.sole_question().unwrap().qclass(), class);
        assert_eq!(app.list_records(zone_name).await, before);
        assert_eq!(app.read_zone_serial(zone_name).await, serial);
    }
}

/// Add and delete records over UDP and TCP without TSIG.
#[tokio::test]
#[serial]
async fn nsupdate_adds_and_deletes_records() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    for send_update in [send_update_udp, send_update_tcp] {
        let owner = format!("www.{zone_name}.");
        let rcode = send_update(
            port,
            &zone_name,
            &[],
            &[UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: "192.0.2.10".to_string(),
            }],
            None,
        )
        .expect("add update");
        assert_eq!(rcode, Rcode::NOERROR);

        let records = app.list_records(&zone_name).await;
        assert!(
            records
                .iter()
                .any(|record| record["name"] == format!("www.{zone_name}.")
                    && record["type"] == "A"
                    && record["value"] == "192.0.2.10"),
            "record was not added: {records:#?}"
        );

        // A second identical add is a silent no-op (RFC 2136, Section 3.4.2.2).
        let rcode = send_update(
            port,
            &zone_name,
            &[],
            &[UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: "192.0.2.10".to_string(),
            }],
            None,
        )
        .expect("duplicate add");
        assert_eq!(rcode, Rcode::NOERROR);
        assert_eq!(app.list_records(&zone_name).await.len(), records.len());

        let rcode = send_update(
            port,
            &zone_name,
            &[],
            &[UpdateRecord::DeleteA {
                name: owner.clone(),
                addr: "192.0.2.10".to_string(),
            }],
            None,
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
        let (status, history) = app
            .send_request(
                reqwest::Method::GET,
                &format!("/zones/{zone_name}/versions"),
                None,
            )
            .await;
        assert_eq!(status, reqwest::StatusCode::OK, "{history}");
        assert_eq!(
            history["items"][0]["change_source"], "nsupdate",
            "{history}"
        );
        assert!(
            history["items"][0].get("changed_by").unwrap().is_null(),
            "{history}"
        );
    }
}

/// Verify that nsupdate deletes every record of a name and type.
#[tokio::test]
#[serial]
async fn nsupdate_deletes_every_record_of_a_name_and_type() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-records.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let owner = format!("multi.{zone_name}.");
    for addr in ["192.0.2.20", "192.0.2.21"] {
        send_update_udp(
            port,
            &zone_name,
            &[],
            &[UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: addr.to_string(),
            }],
            None,
        )
        .expect("add update");
    }

    let rcode = send_update_udp(
        port,
        &zone_name,
        &[],
        &[UpdateRecord::DeleteRecordSet {
            name: owner.clone(),
            rtype: Rtype::A,
        }],
        None,
    )
    .expect("delete every record of the name and type");
    assert_eq!(rcode, Rcode::NOERROR);

    assert!(
        !app.list_records(&zone_name)
            .await
            .iter()
            .any(|record| record["name"] == format!("multi.{zone_name}.")),
        "records were not deleted"
    );
}

/// Verify that nsupdate applies nothing when a prerequisite fails.
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
    let rcode = send_update_udp(
        port,
        &zone_name,
        &[PrerequisiteRecord::NameInUse {
            name: owner.clone(),
        }],
        &[UpdateRecord::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.30".to_string(),
        }],
        None,
    )
    .expect("failing prerequisite");
    assert_eq!(rcode, Rcode::NXDOMAIN);
    assert_eq!(app.list_records(&zone_name).await.len(), before);

    // The matching "must not exist" prerequisite lets the same update through.
    let rcode = send_update_udp(
        port,
        &zone_name,
        &[PrerequisiteRecord::NameNotInUse {
            name: owner.clone(),
        }],
        &[UpdateRecord::AddA {
            name: owner.clone(),
            ttl: 300,
            addr: "192.0.2.30".to_string(),
        }],
        None,
    )
    .expect("passing prerequisite");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.list_records(&zone_name).await.len(), before + 1);
}

/// Verify that a value prerequisite needs every record of the name and type.
#[tokio::test]
#[serial]
async fn a_value_prerequisite_needs_every_record_of_the_name_and_type() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-records.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let owner = format!("check.{zone_name}.");
    for addr in ["192.0.2.1", "192.0.2.2"] {
        let rcode = send_update_udp(
            port,
            &zone_name,
            &[],
            &[UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: addr.to_string(),
            }],
            None,
        )
        .expect("seed the records");
        assert_eq!(rcode, Rcode::NOERROR);
    }
    let before = app.list_records(&zone_name).await.len();
    let update = [UpdateRecord::AddA {
        name: format!("subset.{zone_name}."),
        ttl: 60,
        addr: "192.0.2.99".to_string(),
    }];

    // RFC 2136, Section 3.2.3: the prerequisite record set must equal the zone's,
    // so naming one of its two values is NXRRSET and applies nothing.
    let rcode = send_update_udp(
        port,
        &zone_name,
        &[PrerequisiteRecord::AEquals {
            name: owner.clone(),
            addr: "192.0.2.1".to_string(),
        }],
        &update,
        None,
    )
    .expect("subset prerequisite");
    assert_eq!(rcode, Rcode::NXRRSET);
    assert_eq!(app.list_records(&zone_name).await.len(), before);

    // Both values, in either order, are the whole record set.
    let rcode = send_update_udp(
        port,
        &zone_name,
        &[
            PrerequisiteRecord::AEquals {
                name: owner.clone(),
                addr: "192.0.2.2".to_string(),
            },
            PrerequisiteRecord::AEquals {
                name: owner.clone(),
                addr: "192.0.2.1".to_string(),
            },
        ],
        &update,
        None,
    )
    .expect("whole prerequisite");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.list_records(&zone_name).await.len(), before + 1);
}

/// Verify that a prerequisite may name the zone's SOA, which no row holds
/// (RFC 2136, Section 3.2).
#[tokio::test]
#[serial]
async fn a_prerequisite_may_name_the_zone_soa() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let apex = format!("{zone_name}.");
    let host = format!("host.{zone_name}.");
    let add = [UpdateRecord::AddA {
        name: host.clone(),
        ttl: 300,
        addr: "192.0.2.120".to_string(),
    }];

    for (prerequisites, expected) in [
        (
            vec![PrerequisiteRecord::RecordSetInUse {
                name: apex.clone(),
                rtype: Rtype::SOA,
            }],
            Rcode::NOERROR,
        ),
        (
            vec![PrerequisiteRecord::RecordSetNotInUse {
                name: apex.clone(),
                rtype: Rtype::SOA,
            }],
            Rcode::YXRRSET,
        ),
        (
            vec![PrerequisiteRecord::RecordSetInUse {
                name: host.clone(),
                rtype: Rtype::SOA,
            }],
            Rcode::NXRRSET,
        ),
    ] {
        let rcode =
            send_update_udp(app.dns_port(), zone_name, &prerequisites, &add, None).expect("update");
        assert_eq!(rcode, expected, "{prerequisites:?}");
    }

    // The value-dependent form compares with the SOA served, serial included.
    let serial = u32::try_from(app.read_zone_serial(zone_name).await).unwrap();
    let served_soa = |serial: u32| {
        Soa::new(
            parse_name(&format!("ns1.{zone_name}")).unwrap(),
            parse_name("admin.example.com").unwrap(),
            Serial::from(serial),
            Ttl::from_secs(7200),
            Ttl::from_secs(3600),
            Ttl::from_secs(604800),
            Ttl::from_secs(86400),
        )
    };
    for (soa, expected) in [
        (served_soa(serial), Rcode::NOERROR),
        (served_soa(serial + 1), Rcode::NXRRSET),
    ] {
        let rcode = send_update_udp(
            app.dns_port(),
            zone_name,
            &[PrerequisiteRecord::SoaEquals {
                name: apex.clone(),
                soa,
            }],
            &add,
            None,
        )
        .expect("update");
        assert_eq!(rcode, expected);
    }
}

/// Verify that `nsupdate` refuses an owner outside the zone.
#[tokio::test]
#[serial]
async fn nsupdate_refuses_an_owner_outside_the_zone() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-notzone.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let rcode = send_update_udp(
        app.dns_port(),
        &zone_name,
        &[],
        &[UpdateRecord::AddA {
            name: "www.elsewhere.example.".to_string(),
            ttl: 300,
            addr: "192.0.2.40".to_string(),
        }],
        None,
    )
    .expect("out-of-zone update");

    assert_eq!(rcode, Rcode::NOTZONE);
}

/// Verify that every delete passes the zone prescan before it can be ignored
/// (RFC 2136, Section 3.4.1), and a rejected batch changes neither data nor serial.
#[tokio::test]
#[serial]
async fn nsupdate_prescans_ignored_deletes() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-prescan.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let before = app.list_records(&zone_name).await;
    let serial = app.read_zone_serial(&zone_name).await;

    // SOA has two root names and five integers; HINFO has two empty strings.
    // TYPE65280 is private-use data, distinct from a query or meta type.
    for (rtype, rdata) in [
        (Rtype::SOA, vec![0; 22]),
        (Rtype::HINFO, vec![0; 2]),
        (Rtype::from_int(65280), vec![1]),
    ] {
        for owner in [
            format!("host.{zone_name}."),
            "outside.example.net.".to_string(),
            format!(r"outside\.{zone_name}."),
            ".".to_string(),
        ] {
            let in_zone = owner == format!("host.{zone_name}.");
            for delete in [
                UpdateRecord::DeleteRecordSet {
                    name: owner.clone(),
                    rtype,
                },
                UpdateRecord::DeleteRecord {
                    name: owner.clone(),
                    rtype,
                    rdata: rdata.clone(),
                },
            ] {
                let mut updates = vec![delete];
                if !in_zone {
                    // Put a real change before the bad delete: prescan must
                    // reject the whole message before any operation is applied.
                    updates.insert(
                        0,
                        UpdateRecord::AddA {
                            name: format!("must-not-exist.{zone_name}."),
                            ttl: 300,
                            addr: "192.0.2.123".to_string(),
                        },
                    );
                }
                let rcode = send_update_udp(app.dns_port(), &zone_name, &[], &updates, None)
                    .expect("delete update");
                assert_eq!(
                    rcode,
                    if in_zone {
                        Rcode::NOERROR
                    } else {
                        Rcode::NOTZONE
                    },
                    "{updates:?}"
                );
                assert_eq!(app.list_records(&zone_name).await, before, "{updates:?}");
                assert_eq!(
                    app.read_zone_serial(&zone_name).await,
                    serial,
                    "{updates:?}"
                );
            }
        }
    }
}

/// Verify that a query or meta type is FORMERR even in an otherwise ignored
/// delete, with no partial writes (RFC 2136, Section 3.4.1.2).
#[tokio::test]
#[serial]
async fn nsupdate_prescans_delete_types() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-meta.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let before = app.list_records(&zone_name).await;
    let serial = app.read_zone_serial(&zone_name).await;
    for rtype in [
        Rtype::AXFR,
        Rtype::IXFR,
        Rtype::MAILA,
        Rtype::MAILB,
        Rtype::OPT,
        Rtype::TKEY,
        Rtype::TSIG,
        Rtype::from_int(128),
        Rtype::from_int(248),
        Rtype::from_int(0),
        Rtype::from_int(65535),
    ] {
        for delete in [
            UpdateRecord::DeleteRecordSet {
                name: format!("host.{zone_name}."),
                rtype,
            },
            UpdateRecord::DeleteRecord {
                name: format!("host.{zone_name}."),
                rtype,
                rdata: vec![1],
            },
        ] {
            let updates = [
                UpdateRecord::AddA {
                    name: format!("must-not-exist.{zone_name}."),
                    ttl: 300,
                    addr: "192.0.2.124".to_string(),
                },
                delete,
            ];
            let rcode = send_update_udp(app.dns_port(), &zone_name, &[], &updates, None)
                .expect("meta-type delete");
            assert_eq!(rcode, Rcode::FORMERR, "{updates:?}");
            assert_eq!(app.list_records(&zone_name).await, before, "{updates:?}");
            assert_eq!(
                app.read_zone_serial(&zone_name).await,
                serial,
                "{updates:?}"
            );
        }
    }
}

/// Verify that TCP prescan errors retain TSIG authentication, and the zone
/// lookup precedes the prescan (RFC 2136, Sections 3.1 and 3.4.1).
#[tokio::test]
#[serial]
async fn nsupdate_prescan_errors_are_signed_over_tcp() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "prescan-key", KeyRole::Admin).await;
    let before = app.list_records(zone_name).await;
    let serial = app.read_zone_serial(zone_name).await;
    let missing = app.zone_name("missing-prescan.example");
    for (target, owner, rtype, expected) in [
        (
            zone_name,
            "outside.example.net.".to_string(),
            Rtype::SOA,
            Rcode::NOTZONE,
        ),
        (
            zone_name,
            format!("host.{zone_name}."),
            Rtype::AXFR,
            Rcode::FORMERR,
        ),
        // The missing authority is answered before the malformed update.
        (
            missing.as_str(),
            "outside.example.net.".to_string(),
            Rtype::AXFR,
            Rcode::NOTAUTH,
        ),
    ] {
        let updates = [
            UpdateRecord::AddA {
                name: format!("must-not-exist.{target}."),
                ttl: 300,
                addr: "192.0.2.125".to_string(),
            },
            UpdateRecord::DeleteRecordSet { name: owner, rtype },
        ];
        let rcode = send_update_tcp(app.dns_port(), target, &[], &updates, Some(&key))
            .expect("signed response");
        assert_eq!(rcode, expected, "{updates:?}");
        assert_eq!(app.list_records(zone_name).await, before);
        assert_eq!(app.read_zone_serial(zone_name).await, serial);
    }
    // A correctly formed SOA delete remains a successful no-op, under TSIG too.
    let rcode = send_update_tcp(
        app.dns_port(),
        zone_name,
        &[],
        &[UpdateRecord::DeleteRecordSet {
            name: format!("{zone_name}."),
            rtype: Rtype::SOA,
        }],
        Some(&key),
    )
    .expect("signed no-op");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.list_records(zone_name).await, before);
    assert_eq!(app.read_zone_serial(zone_name).await, serial);
}

/// Verify that nsupdate advances the zone serial once per message.
#[tokio::test]
#[serial]
async fn nsupdate_advances_the_zone_serial_once_per_message() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-serial.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();

    let before = app.read_zone_serial(&zone_name).await;

    let owner = format!("pair.{zone_name}.");
    let rcode = send_update_udp(
        port,
        &zone_name,
        &[],
        &[
            UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: "192.0.2.50".to_string(),
            },
            UpdateRecord::AddA {
                name: owner.clone(),
                ttl: 300,
                addr: "192.0.2.51".to_string(),
            },
        ],
        None,
    )
    .expect("two-record update");
    assert_eq!(rcode, Rcode::NOERROR);

    assert_eq!(app.read_zone_serial(&zone_name).await, before + 1);

    // An update that changes nothing must leave the serial alone, or every
    // no-op would make secondaries re-transfer.
    let rcode = send_update_udp(
        port,
        &zone_name,
        &[],
        &[UpdateRecord::DeleteA {
            name: owner,
            addr: "198.51.100.1".to_string(),
        }],
        None,
    )
    .expect("no-op update");
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.read_zone_serial(&zone_name).await, before + 1);
}

/// Verify that replacing an alias needs `record:delete` and retiming a set
/// needs `record:update`, in addition to `record:create`.
#[tokio::test]
#[serial]
async fn a_create_grant_alone_rewrites_nothing_that_exists() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("nsupdate-rewrite.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();
    let key = create_tsig_key(&app, "nsupdate-rewrite-key", KeyRole::Own).await;
    app.run_cli_success(
        &[
            "role",
            "grant",
            &key.name,
            "--zone",
            &zone_name,
            "--actions",
            "record:create",
        ],
        None,
    )
    .await;
    let alias = format!("alias.{zone_name}.");
    let host = format!("host.{zone_name}.");

    for updates in [
        vec![UpdateRecord::AddCname {
            name: alias.clone(),
            ttl: 300,
            target: "one.example.net.".to_string(),
        }],
        vec![UpdateRecord::AddA {
            name: host.clone(),
            ttl: 300,
            addr: "192.0.2.130".to_string(),
        }],
    ] {
        let rcode = send_update_udp(port, &zone_name, &[], &updates, Some(&key)).expect("update");
        assert_eq!(rcode, Rcode::NOERROR, "{updates:?}");
    }

    // Replacing the CNAME deletes it; a new TTL rewrites the A set.
    let replace = vec![UpdateRecord::AddCname {
        name: alias.clone(),
        ttl: 300,
        target: "two.example.net.".to_string(),
    }];
    let retime = vec![UpdateRecord::AddA {
        name: host.clone(),
        ttl: 600,
        addr: "192.0.2.131".to_string(),
    }];
    for updates in [&replace, &retime] {
        let rcode = send_update_udp(port, &zone_name, &[], updates, Some(&key)).expect("update");
        assert_eq!(rcode, Rcode::REFUSED, "{updates:?}");
    }

    app.run_cli_success(
        &[
            "role",
            "grant",
            &key.name,
            "--zone",
            &zone_name,
            "--actions",
            "record:update,record:delete",
        ],
        None,
    )
    .await;
    for updates in [&replace, &retime] {
        let rcode = send_update_udp(port, &zone_name, &[], updates, Some(&key)).expect("update");
        assert_eq!(rcode, Rcode::NOERROR, "{updates:?}");
    }
}

/// Verify that signed updates require a zone grant for their TSIG key.
#[tokio::test]
#[serial]
async fn signed_nsupdate_needs_a_grant_for_the_zone() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("nsupdate-policy.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();
    let key = create_tsig_key(&app, "nsupdate-policy-key", KeyRole::Own).await;

    let add = |owner: String| UpdateRecord::AddA {
        name: owner,
        ttl: 300,
        addr: "192.0.2.60".to_string(),
    };

    // No grant gives this key anything in the zone.
    let rcode = send_update_udp(
        port,
        &zone_name,
        &[],
        &[add(format!("a.{zone_name}."))],
        Some(&key),
    )
    .expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    // Granting only `a` leaves every other owner name refused.
    app.run_cli_success(
        &[
            "role",
            "grant",
            &key.name,
            "--zone",
            &zone_name,
            "--actions",
            "record:create",
            "--pattern",
            "a",
        ],
        None,
    )
    .await;

    let rcode = send_update_udp(
        port,
        &zone_name,
        &[],
        &[add(format!("b.{zone_name}."))],
        Some(&key),
    )
    .expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    let rcode = send_update_udp(
        port,
        &zone_name,
        &[],
        &[add(format!("a.{zone_name}."))],
        Some(&key),
    )
    .expect("send");
    assert_eq!(rcode, Rcode::NOERROR);

    assert!(
        app.list_records(&zone_name)
            .await
            .iter()
            .any(|record| record["name"] == format!("a.{zone_name}.")),
        "granted update was not applied"
    );

    // An add is `record:create`; deleting what it added is a separate action.
    let delete = UpdateRecord::DeleteA {
        name: format!("a.{zone_name}."),
        addr: "192.0.2.60".to_string(),
    };
    let rcode = send_update_udp(port, &zone_name, &[], &[delete], Some(&key)).expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    // The DNS plane has no API token, so the key that signed the update is
    // the name the change is recorded under.
    let (status, body) = app
        .send_request(
            reqwest::Method::GET,
            &format!("/zones/{zone_name}/versions"),
            None,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["items"][0]["change_source"], "nsupdate", "{body}");
    assert_eq!(
        body["items"][0]["changed_by"],
        serde_json::json!({"kind": "tsig_key", "name": key.name}),
        "{body}"
    );
}

/// Verify that a signed prerequisite needs a grant reaching what it names.
#[tokio::test]
#[serial]
async fn a_signed_prerequisite_needs_a_grant_reaching_what_it_names() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("nsupdate-prereq.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let port = app.dns_port();
    let key = create_tsig_key(&app, "nsupdate-prereq-key", KeyRole::Own).await;
    app.run_cli_success(
        &[
            "role",
            "grant",
            &key.name,
            "--zone",
            &zone_name,
            "--actions",
            "record:read,record:create",
            "--pattern",
            "*.dyn",
            "--types",
            "A",
        ],
        None,
    )
    .await;

    // The answer must not depend on whether `secret` exists.
    let secret = || PrerequisiteRecord::NameNotInUse {
        name: format!("secret.{zone_name}."),
    };
    let rcode = send_update_udp(port, &zone_name, &[secret()], &[], Some(&key)).expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    let (status, body) = app
        .send_request(
            reqwest::Method::POST,
            "/records",
            Some(serde_json::json!({
                "name": "secret",
                "type": "A",
                "value": "192.0.2.1",
                "zone_name": zone_name,
            })),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "{body}");
    let rcode = send_update_udp(port, &zone_name, &[secret()], &[], Some(&key)).expect("send");
    assert_eq!(rcode, Rcode::REFUSED);

    // Inside the grant the prerequisite is answered, before and after the add.
    let host = format!("host.dyn.{zone_name}.");
    let equals = || PrerequisiteRecord::AEquals {
        name: host.clone(),
        addr: "192.0.2.60".to_string(),
    };
    let rcode = send_update_udp(port, &zone_name, &[equals()], &[], Some(&key)).expect("send");
    assert_eq!(rcode, Rcode::NXRRSET);
    let add = UpdateRecord::AddA {
        name: host.clone(),
        ttl: 300,
        addr: "192.0.2.60".to_string(),
    };
    let rcode = send_update_udp(port, &zone_name, &[], &[add], Some(&key)).expect("send");
    assert_eq!(rcode, Rcode::NOERROR);
    let rcode = send_update_udp(port, &zone_name, &[equals()], &[], Some(&key)).expect("send");
    assert_eq!(rcode, Rcode::NOERROR);
}

/// Verify that nsupdate maps the input apex `@` to the empty stored owner.
#[tokio::test]
#[serial]
async fn nsupdate_adds_at_the_zone_apex() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-apex.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let rcode = send_update_udp(
        app.dns_port(),
        &zone_name,
        &[],
        &[UpdateRecord::AddA {
            name: format!("{zone_name}."),
            ttl: 300,
            addr: "192.0.2.60".to_string(),
        }],
        None,
    )
    .expect("apex add");
    assert_eq!(rcode, Rcode::NOERROR);

    assert!(
        app.list_records(&zone_name)
            .await
            .iter()
            .any(|record| record["name"] == format!("{zone_name}.")
                && record["type"] == "A"
                && record["value"] == "192.0.2.60"),
        "apex record was not added"
    );
}

/// Verify NOTAUTH for unserved zones and NOTZONE for out-of-zone owners
/// (RFC 2136, Section 3.1.2).
#[tokio::test]
#[serial]
async fn nsupdate_answers_notauth_for_a_zone_it_does_not_serve() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-notauth.example");

    let rcode = send_update_udp(
        app.dns_port(),
        &zone_name,
        &[],
        &[UpdateRecord::AddA {
            name: format!("host.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.70".to_string(),
        }],
        None,
    )
    .expect("update for an unknown zone");

    assert_eq!(rcode, Rcode::NOTAUTH);
}

/// Verify that a delete leaves the apex NS set standing and passes over the
/// SOA (RFC 2136, Sections 3.4.2.3 and 3.4.2.4).
#[tokio::test]
#[serial]
async fn nsupdate_keeps_the_apex_ns_set() {
    let app = unsigned_nsupdate_app().await;
    let zone_name = app.zone_name("nsupdate-apex-ns.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let apex = format!("{zone_name}.");
    let apex_ns = |records: &[Value]| -> Vec<String> {
        records
            .iter()
            .filter(|record| record["name"] == apex && record["type"] == "NS")
            .map(|record| record["value"].as_str().unwrap().to_string())
            .collect()
    };
    let seeded = apex_ns(&app.list_records(&zone_name).await);
    assert_eq!(seeded.len(), 1, "zone creation seeds one apex NS");

    // The NS set survives a delete of the type, of the only NS, and of the
    // whole name; the SOA delete is passed over rather than refused.
    let apex_a = UpdateRecord::AddA {
        name: apex.clone(),
        ttl: 300,
        addr: "192.0.2.80".to_string(),
    };
    for updates in [
        vec![UpdateRecord::DeleteRecordSet {
            name: apex.clone(),
            rtype: Rtype::NS,
        }],
        vec![UpdateRecord::DeleteNs {
            name: apex.clone(),
            target: seeded[0].clone(),
        }],
        vec![UpdateRecord::DeleteRecordSet {
            name: apex.clone(),
            rtype: Rtype::SOA,
        }],
        vec![
            apex_a,
            UpdateRecord::DeleteRecordSet {
                name: apex.clone(),
                rtype: Rtype::ANY,
            },
        ],
    ] {
        let rcode =
            send_update_udp(app.dns_port(), &zone_name, &[], &updates, None).expect("apex delete");
        assert_eq!(rcode, Rcode::NOERROR, "{updates:?}");
    }

    let records = app.list_records(&zone_name).await;
    assert_eq!(apex_ns(&records), seeded);
    assert!(
        !records
            .iter()
            .any(|record| record["name"] == apex && record["type"] == "A"),
        "the whole-name delete removed the apex A"
    );
}

/// Verify that CNAME/data conflicts are ignored and a second CNAME replaces the first
/// (RFC 2136, Section 3.4.2.2).
#[tokio::test]
#[serial]
async fn nsupdate_passes_over_a_cname_conflict_and_replaces_a_cname() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let www = format!("www.{zone_name}.");
    let alias = format!("alias.{zone_name}.");
    let records_at = |records: &[Value], name: &str| -> Vec<(String, String, u64)> {
        records
            .iter()
            .filter(|record| record["name"] == name)
            .map(|record| {
                (
                    record["type"].as_str().unwrap().to_string(),
                    record["value"].as_str().unwrap().to_string(),
                    record["ttl"].as_u64().unwrap(),
                )
            })
            .collect()
    };

    for updates in [
        vec![UpdateRecord::AddA {
            name: www.clone(),
            ttl: 300,
            addr: "192.0.2.90".to_string(),
        }],
        // A CNAME beside the A: passed over.
        vec![UpdateRecord::AddCname {
            name: www.clone(),
            ttl: 300,
            target: format!("target.{zone_name}."),
        }],
        vec![UpdateRecord::AddCname {
            name: alias.clone(),
            ttl: 300,
            target: format!("one.{zone_name}."),
        }],
        // An A beside the CNAME: passed over.
        vec![UpdateRecord::AddA {
            name: alias.clone(),
            ttl: 300,
            addr: "192.0.2.91".to_string(),
        }],
        // A second CNAME replaces the first, TTL included.
        vec![UpdateRecord::AddCname {
            name: alias.clone(),
            ttl: 600,
            target: format!("two.{zone_name}."),
        }],
    ] {
        let rcode =
            send_update_udp(app.dns_port(), zone_name, &[], &updates, None).expect("update");
        assert_eq!(rcode, Rcode::NOERROR, "{updates:?}");
    }

    let records = app.list_records(zone_name).await;
    assert_eq!(
        records_at(&records, &www),
        [("A".to_string(), "192.0.2.90".to_string(), 300)]
    );
    assert_eq!(
        records_at(&records, &alias),
        [("CNAME".to_string(), format!("two.{zone_name}."), 600)]
    );
}

/// Verify that an add with a new TTL moves the whole record set to it, as
/// RFC 2181, Section 5.2 keeps one TTL per set.
#[tokio::test]
#[serial]
async fn nsupdate_moves_a_record_set_to_the_added_ttl() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let host = format!("host.{zone_name}.");

    for (ttl, addr) in [
        (300, "192.0.2.100"),
        (600, "192.0.2.101"),
        (900, "192.0.2.100"),
    ] {
        let rcode = send_update_udp(
            app.dns_port(),
            zone_name,
            &[],
            &[UpdateRecord::AddA {
                name: host.clone(),
                ttl,
                addr: addr.to_string(),
            }],
            None,
        )
        .expect("add");
        assert_eq!(rcode, Rcode::NOERROR);
    }

    // The third add repeated an rdata with yet another TTL: the set follows.
    let ttls: Vec<u64> = app
        .list_records(zone_name)
        .await
        .iter()
        .filter(|record| record["name"] == host)
        .map(|record| record["ttl"].as_u64().unwrap())
        .collect();
    assert_eq!(ttls, [900, 900]);
}

/// Verify that a signed request the parser rejects is still answered under
/// its key (RFC 8945, Section 5.2), as a signed FORMERR.
#[tokio::test]
#[serial]
async fn a_signed_request_that_does_not_parse_is_answered_under_its_key() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "formerr-key", KeyRole::Admin).await;

    let (rcode, signed) =
        send_signed_update_with_two_zones(app.dns_port(), zone_name, &key).expect("update");

    assert_eq!(rcode, Rcode::FORMERR);
    assert!(signed, "the FORMERR was not signed");
}

/// Verify that a signed request's BADVERS is answered under its key
/// (RFC 8945, Section 5.3).
#[tokio::test]
#[serial]
async fn a_signed_request_with_a_newer_edns_is_answered_under_its_key() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "badvers-key", KeyRole::Admin).await;

    let (rcode, signed) =
        send_signed_update_with_edns_version(app.dns_port(), zone_name, &key, 1).expect("update");

    assert_eq!(rcode, OptRcode::BADVERS);
    assert!(signed, "the BADVERS was not signed");
}

/// Echo DO in signed UPDATE success and BADVERS responses over UDP and TCP.
#[tokio::test]
#[serial]
async fn edns_dnssec_ok_is_echoed_in_update_responses() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "update-dnssec-ok-key", KeyRole::Admin).await;
    for dnssec_ok in [false, true] {
        for version in [0, 1] {
            for tcp in [false, true] {
                let mut query = build_update(3225, zone_name, Class::IN, &[], &[]).unwrap();
                query
                    .opt(|opt| {
                        opt.set_udp_payload_size(4096);
                        opt.set_version(version);
                        opt.set_dnssec_ok(dnssec_ok);
                        Ok(())
                    })
                    .unwrap();
                let response = exchange_request(query, Some(&key), |message| {
                    if tcp {
                        exchange_tcp(app.dns_port(), message)
                    } else {
                        exchange_udp(app.dns_port(), message)
                    }
                })
                .unwrap();
                let opt = response.opt().unwrap();
                assert_eq!(opt.dnssec_ok(), dnssec_ok);
                assert_eq!(opt.version(), 0);
                assert_eq!(
                    opt.rcode(response.header()),
                    if version == 0 {
                        OptRcode::NOERROR
                    } else {
                        OptRcode::BADVERS
                    }
                );
            }
        }
    }
}

/// Reject stale signed UPDATEs with a verifiable BADTIME and OPT.
#[tokio::test]
#[serial]
async fn badtime_update_responses_preserve_edns_and_verify() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "badtime-update-key", KeyRole::Admin).await;
    let signed_at = Time48::from_u64(u64::from(Time48::now()) - 3600);
    for dnssec_ok in [false, true] {
        let mut query = build_update(8945, zone_name, Class::IN, &[], &[]).unwrap();
        query
            .opt(|opt| {
                opt.set_udp_payload_size(4096);
                opt.set_dnssec_ok(dnssec_ok);
                Ok(())
            })
            .unwrap();
        ClientTransaction::request_with_fudge(
            key.to_tsig_key().unwrap(),
            &mut query,
            signed_at,
            17,
        )
        .unwrap();
        let query = query.finish();
        for response in [
            exchange_udp(app.dns_port(), &query).unwrap(),
            exchange_tcp(app.dns_port(), &query).unwrap(),
        ] {
            let response = Message::from_octets(response).unwrap();
            assert_eq!(response.header().id(), 8945);
            assert!(response.header().qr());
            assert_eq!(response.header().opcode(), Opcode::UPDATE);
            assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
            assert_eq!(response.opt().unwrap().dnssec_ok(), dnssec_ok);
            let tsig = response
                .additional()
                .unwrap()
                .limit_to::<Tsig<_, _>>()
                .last()
                .unwrap()
                .unwrap();
            assert_eq!(tsig.data().error(), TsigRcode::BADTIME);
            assert_eq!(tsig.data().time_signed(), signed_at);
            assert_eq!(tsig.data().fudge(), 17);
            assert_eq!(tsig.data().other().len(), 6);
            verify_response_mac(&query, &response, &key).unwrap();
        }
    }
}

/// Authenticate truncated UPDATEs before applying time and length policy.
#[tokio::test]
#[serial]
async fn truncated_updates_follow_tsig_validation_order() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "truncated-update-key", KeyRole::Admin).await;
    for (age, corrupt, expected) in [
        (0, false, TsigRcode::BADTRUNC),
        (3600, false, TsigRcode::BADTIME),
        (0, true, TsigRcode::BADSIG),
        (3600, true, TsigRcode::BADSIG),
    ] {
        let signed_at = Time48::from_u64(u64::from(Time48::now()) - age);
        let mut query = build_update(8945, zone_name, Class::IN, &[], &[]).unwrap();
        query
            .opt(|opt| {
                opt.set_udp_payload_size(1232);
                opt.set_dnssec_ok(true);
                Ok(())
            })
            .unwrap();
        ClientTransaction::request_with_fudge(
            key.to_tsig_key_with_mac_len(16).unwrap(),
            &mut query,
            signed_at,
            17,
        )
        .unwrap();
        let mut query = query.finish();
        if corrupt {
            let mac_end = query.len() - 7;
            query[mac_end] ^= 1;
        }
        for response in [
            exchange_udp(app.dns_port(), &query).unwrap(),
            exchange_tcp(app.dns_port(), &query).unwrap(),
        ] {
            let response = Message::from_octets(response).unwrap();
            assert_eq!(response.header().id(), 8945);
            assert_eq!(response.header().opcode(), Opcode::UPDATE);
            assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
            assert!(response.opt().unwrap().dnssec_ok());
            let tsig = response
                .additional()
                .unwrap()
                .limit_to::<Tsig<_, _>>()
                .last()
                .unwrap()
                .unwrap();
            assert_eq!(tsig.data().error(), expected);
            if corrupt {
                assert!(tsig.data().mac().is_empty());
            } else {
                assert_eq!(tsig.data().mac().len(), 32);
                verify_response_mac(&query, &response, &key).unwrap();
            }
            assert_eq!(
                tsig.data().other().len(),
                if expected == TsigRcode::BADTIME { 6 } else { 0 }
            );
        }
    }
}

/// Verify the DNAME rules of RFC 6672: a DNAME beside a CNAME is passed
/// over, a second DNAME replaces the first, a name below one is refused.
#[tokio::test]
#[serial]
async fn nsupdate_replaces_a_dname_and_passes_over_one_beside_a_cname() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let alias = format!("alias.{zone_name}.");
    let tree = format!("tree.{zone_name}.");
    let records_at = |records: &[Value], name: &str| -> Vec<(String, String, u64)> {
        records
            .iter()
            .filter(|record| record["name"] == name)
            .map(|record| {
                (
                    record["type"].as_str().unwrap().to_string(),
                    record["value"].as_str().unwrap().to_string(),
                    record["ttl"].as_u64().unwrap(),
                )
            })
            .collect()
    };

    for (updates, expected) in [
        (
            vec![UpdateRecord::AddCname {
                name: alias.clone(),
                ttl: 300,
                target: "www.example.net.".to_string(),
            }],
            Rcode::NOERROR,
        ),
        // A DNAME beside the CNAME: passed over.
        (
            vec![UpdateRecord::AddDname {
                name: alias.clone(),
                ttl: 300,
                target: "one.example.net.".to_string(),
            }],
            Rcode::NOERROR,
        ),
        (
            vec![UpdateRecord::AddDname {
                name: tree.clone(),
                ttl: 300,
                target: "one.example.net.".to_string(),
            }],
            Rcode::NOERROR,
        ),
        // A second DNAME replaces the first, TTL included.
        (
            vec![UpdateRecord::AddDname {
                name: tree.clone(),
                ttl: 600,
                target: "two.example.net.".to_string(),
            }],
            Rcode::NOERROR,
        ),
        // Nothing may exist below a DNAME.
        (
            vec![UpdateRecord::AddA {
                name: format!("leaf.tree.{zone_name}."),
                ttl: 300,
                addr: "192.0.2.110".to_string(),
            }],
            Rcode::REFUSED,
        ),
    ] {
        let rcode =
            send_update_udp(app.dns_port(), zone_name, &[], &updates, None).expect("update");
        assert_eq!(rcode, expected, "{updates:?}");
    }

    let records = app.list_records(zone_name).await;
    assert_eq!(
        records_at(&records, &alias),
        [("CNAME".to_string(), "www.example.net.".to_string(), 300)]
    );
    assert_eq!(
        records_at(&records, &tree),
        [("DNAME".to_string(), "two.example.net.".to_string(), 600)]
    );
}
