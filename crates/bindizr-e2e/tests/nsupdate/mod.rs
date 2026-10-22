use domain::{
    base::{
        Message, Name, Rtype, Serial, Ttl,
        iana::{Class, Opcode, OptRcode, Rcode, TsigRcode},
    },
    rdata::{
        Soa,
        tsig::{Time48, Tsig},
    },
    tsig::ClientTransaction,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use serial_test::serial;

use crate::common::{
    TestApp, TestAppOptions,
    dns::{
        exchange_request, exchange_udp, fetch_exported_record_sets,
        nsupdate::{
            PrerequisiteRecord, UpdateRecord, build_update, send_signed_update_with_edns_version,
            send_signed_update_with_two_zones, send_update_tcp, send_update_udp,
        },
        parse_name,
        tsig::{KeyRole, create_tsig_key, verify_response_mac},
    },
    exchange_tcp,
};

/// Preserve root targets through signed updates, transfers, and DNSSEC.
#[tokio::test]
#[serial]
async fn nsupdate_root_targets_round_trip_through_signed_zone() {
    use domain::{
        base::{MessageBuilder, ToName, UnknownRecordData, rdata::ComposeRecordData},
        dep::octseq::parse::Parser,
        rdata::{Dnskey, Rrsig},
    };
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let name = zone["name"].as_str().unwrap();

    let key = create_tsig_key(&app, "root-target-key", KeyRole::Admin).await;

    let targets = [
        ("ns", Rtype::NS),
        ("cname", Rtype::CNAME),
        ("ptr", Rtype::PTR),
        ("dname", Rtype::DNAME),
    ];
    let updates: Vec<_> = targets
        .iter()
        .map(|(owner, rtype)| UpdateRecord::AddRecord {
            name: format!("{owner}.{name}."),
            rtype: *rtype,
            ttl: 300,
            rdata: vec![0],
        })
        .collect();

    assert_eq!(
        send_update_tcp(app.dns_port(), name, &[], &updates, Some(&key)).unwrap(),
        Rcode::NOERROR,
    );

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{name}/dnssec"),
            Some(json!({"parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let sets = fetch_exported_record_sets(&app, name).await;
    let public_keys: Vec<_> = sets[&(format!("{name}."), Rtype::DNSKEY)]
        .iter()
        .map(|data| {
            let key = Dnskey::parse(&mut Parser::from_ref(data)).unwrap();
            let mut point = vec![4];
            point.extend_from_slice(key.public_key());
            point
        })
        .collect();

    for (owner, rtype) in targets {
        let owner = format!("{owner}.{name}.");

        assert_eq!(sets[&(owner.clone(), rtype)], [vec![0]]);

        // Delegation NS data remains unsigned (RFC 4035, Section 2.2).
        if rtype == Rtype::NS {
            assert!(!sets.contains_key(&(owner, Rtype::RRSIG)));
            continue;
        }

        let signatures: Vec<_> = sets[&(owner.clone(), Rtype::RRSIG)]
            .iter()
            .map(|data| Rrsig::parse(&mut Parser::from_ref(data)).unwrap())
            .filter(|signature| signature.type_covered() == rtype)
            .collect();

        assert!(!signatures.is_empty());

        for signature in signatures {
            let mut signed_data = Vec::new();
            signature.compose_canonical_rdata(&mut signed_data).unwrap();
            signed_data.truncate(signed_data.len() - signature.signature().len());
            parse_name(&owner)
                .unwrap()
                .compose_canonical(&mut signed_data)
                .unwrap();
            signed_data.extend_from_slice(&rtype.to_int().to_be_bytes());
            signed_data.extend_from_slice(&Class::IN.to_int().to_be_bytes());
            signed_data.extend_from_slice(&signature.original_ttl().as_secs().to_be_bytes());
            signed_data.extend_from_slice(&[0, 1, 0]);

            assert!(public_keys.iter().any(|public| {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
                    .verify(&signed_data, signature.signature())
                    .is_ok()
            }));
        }
    }

    let mut question = MessageBuilder::new_vec().question();
    question
        .push((&parse_name(name).unwrap(), Rtype::AXFR))
        .unwrap();
    let response = exchange_request(question.additional(), Some(&key), |request| {
        exchange_tcp(app.dns_port(), request)
    })
    .unwrap();

    assert_eq!(response.header().rcode(), Rcode::NOERROR);

    for (owner, rtype) in targets {
        let record = response
            .answer()
            .unwrap()
            .map(Result::unwrap)
            .find(|record| {
                record.rtype() == rtype && record.owner().to_string() == format!("{owner}.{name}")
            })
            .unwrap();

        assert_eq!(
            record
                .to_record::<UnknownRecordData<_>>()
                .unwrap()
                .unwrap()
                .data()
                .data(),
            &[0]
        );
    }

    for (owner, rtype) in targets {
        let owner = format!("{owner}.{name}.");
        let prerequisites = [PrerequisiteRecord::RecordEquals {
            name: owner.clone(),
            rtype,
            rdata: vec![0],
        }];
        let delete = [UpdateRecord::DeleteRecord {
            name: owner.clone(),
            rtype,
            rdata: vec![0],
        }];

        assert_eq!(
            send_update_udp(app.dns_port(), name, &prerequisites, &delete, Some(&key)).unwrap(),
            Rcode::NOERROR,
        );
        assert!(
            !fetch_exported_record_sets(&app, name)
                .await
                .contains_key(&(owner, rtype))
        );
        assert_eq!(
            send_update_tcp(app.dns_port(), name, &prerequisites, &[], Some(&key)).unwrap(),
            Rcode::NXRRSET,
        );
    }
}

/// Misplaced TSIG is FORMERR before authority or grants, with no partial write.
#[tokio::test]
#[serial]
async fn nsupdate_rejects_tsig_outside_additional_without_mutating_zone() {
    for tsig_required in [false, true] {
        let app = TestApp::start_with_options(TestAppOptions {
            nsupdate_tsig_required: tsig_required,
            ..Default::default()
        })
        .await;
        let zone = app.create_test_zone().await;
        let zone_name = zone["name"].as_str().unwrap();

        let serial = app.read_zone_serial(zone_name).await;
        let records = fetch_exported_record_sets(&app, zone_name).await;

        for prerequisite in [false, true] {
            for owner in [zone_name, "outside.invalid"] {
                for additional_tsig in [false, true] {
                    let mut request = build_update(
                        8945,
                        zone_name,
                        Class::IN,
                        &[],
                        &[UpdateRecord::AddA {
                            name: format!("host.{zone_name}."),
                            ttl: 300,
                            addr: "192.0.2.1".into(),
                        }],
                    )
                    .unwrap()
                    .finish();
                    let message = Message::from_octets(request.as_slice()).unwrap();
                    let offset = if prerequisite {
                        message.answer().unwrap().pos()
                    } else {
                        message.additional().unwrap().pos()
                    };
                    let mut record = parse_name(owner).unwrap().as_slice().to_vec();
                    let mut rdata = parse_name("hmac-sha256").unwrap().as_slice().to_vec();
                    rdata.extend_from_slice(&Time48::now().into_octets());
                    rdata.extend_from_slice(&300u16.to_be_bytes());
                    rdata.extend_from_slice(&32u16.to_be_bytes());
                    rdata.extend_from_slice(&[0; 32]);
                    rdata.extend_from_slice(&8945u16.to_be_bytes());
                    rdata.extend_from_slice(&[0; 4]);
                    record.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
                    record.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
                    record.extend_from_slice(&rdata);
                    request.splice(offset..offset, record.iter().copied());
                    let (count_offset, count) = if prerequisite { (6, 1u16) } else { (8, 2u16) };
                    request[count_offset..count_offset + 2].copy_from_slice(&count.to_be_bytes());

                    if additional_tsig {
                        request.extend_from_slice(&record);
                        request[10..12].copy_from_slice(&1u16.to_be_bytes());
                    }

                    for bytes in [
                        exchange_udp(app.dns_port(), &request).unwrap(),
                        exchange_tcp(app.dns_port(), &request).unwrap(),
                    ] {
                        let response = Message::from_octets(bytes).unwrap();

                        assert_eq!(
                            response.header().rcode(),
                            Rcode::FORMERR,
                            "tsig_required={tsig_required}, prerequisite={prerequisite}, owner={owner}"
                        );
                        assert!(!crate::common::dns::tsig::parse_tsig_presence(&response).unwrap());
                    }
                }
            }
        }

        assert_eq!(app.read_zone_serial(zone_name).await, serial);
        assert_eq!(fetch_exported_record_sets(&app, zone_name).await, records);
    }
}

/// Refuse managed changes atomically while keeping DNSSEC prerequisites.
#[tokio::test]
#[serial]
async fn nsupdate_refuses_managed_dnssec_changes_without_mutating_zone() {
    use domain::{base::rdata::ComposeRecordData, rdata::AllRecordData};

    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let name = zone["name"].as_str().unwrap();

    let key = create_tsig_key(&app, "managed-key", KeyRole::Admin).await;
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{name}/dnssec"),
            Some(json!({"parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);

    let serial = app.read_zone_serial(name).await;
    let versions = app
        .send_request(
            Method::GET,
            &format!("/zones/{name}/versions?include_signer_serials=true"),
            None,
        )
        .await
        .1;

    let request = domain::base::MessageBuilder::new_vec().question();
    let mut request = request;
    request
        .push((&parse_name(name).unwrap(), Rtype::AXFR))
        .unwrap();
    let transfer = exchange_request(request.additional(), Some(&key), |request| {
        exchange_tcp(app.dns_port(), request)
    })
    .unwrap();
    let rows = transfer
        .answer()
        .unwrap()
        .limit_to::<AllRecordData<_, _>>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    for row in rows
        .iter()
        .filter(|row| matches!(row.rtype().to_int(), 46..=48 | 50 | 51 | 59 | 60))
    {
        let mut rdata = Vec::new();
        row.data().compose_canonical_rdata(&mut rdata).unwrap();
        let owner = row.owner().to_string();

        assert_eq!(
            send_update_udp(
                app.dns_port(),
                name,
                &[PrerequisiteRecord::RecordSetInUse {
                    name: owner.clone(),
                    rtype: row.rtype()
                }],
                &[],
                Some(&key)
            )
            .unwrap(),
            Rcode::NOERROR
        );

        for operation in [
            UpdateRecord::AddRecord {
                name: owner.clone(),
                rtype: row.rtype(),
                ttl: row.ttl().as_secs(),
                rdata: rdata.clone(),
            },
            UpdateRecord::DeleteRecordSet {
                name: owner.clone(),
                rtype: row.rtype(),
            },
            UpdateRecord::DeleteRecord {
                name: owner.clone(),
                rtype: row.rtype(),
                rdata,
            },
        ] {
            let changes = [
                UpdateRecord::AddA {
                    name: format!("rollback.{name}"),
                    ttl: 3600,
                    addr: "192.0.2.1".into(),
                },
                operation,
            ];

            for tcp in [false, true] {
                let code = if tcp {
                    send_update_tcp(app.dns_port(), name, &[], &changes, Some(&key))
                } else {
                    send_update_udp(app.dns_port(), name, &[], &changes, Some(&key))
                }
                .unwrap();

                assert_eq!(code, Rcode::REFUSED);
            }
        }
    }

    assert_eq!(app.read_zone_serial(name).await, serial);
    assert_eq!(
        app.send_request(
            Method::GET,
            &format!("/zones/{name}/versions?include_signer_serials=true"),
            None
        )
        .await
        .1,
        versions
    );
    assert_eq!(
        send_update_udp(
            app.dns_port(),
            name,
            &[PrerequisiteRecord::NameNotInUse {
                name: format!("rollback.{name}")
            }],
            &[],
            Some(&key)
        )
        .unwrap(),
        Rcode::NOERROR
    );
}

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

    let sets = fetch_exported_record_sets(&app, zone_name).await;
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
        !fetch_exported_record_sets(&app, zone_name)
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
            let exported = fetch_exported_record_sets(&app, zone_name).await;
            assert!(exported[&(format!("naptr.{zone_name}."), Rtype::NAPTR)].contains(&rdata));
        }
    }
}

/// Refuse unserved zone classes before evaluating prerequisites or updates.
#[tokio::test]
#[serial]
async fn nsupdate_returns_notauth_for_unserved_zone_classes_over_udp() {
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
async fn nsupdate_signs_zone_class_refusals_over_tcp() {
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
async fn nsupdate_value_prerequisite_requires_complete_record_set() {
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
async fn nsupdate_prerequisite_accepts_zone_soa() {
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
                        if rtype == Rtype::SOA {
                            Rcode::NOERROR
                        } else {
                            Rcode::FORMERR
                        }
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
async fn nsupdate_signs_prescan_errors_over_tcp() {
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
async fn nsupdate_create_grant_preserves_existing_records() {
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
    let wks = format!("wks.{zone_name}.");

    for updates in [
        vec![UpdateRecord::AddRecord {
            name: wks.clone(),
            rtype: Rtype::from_int(11),
            ttl: 300,
            rdata: vec![192, 0, 2, 1, 6, 0x80],
        }],
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
    let wks_replace = vec![
        UpdateRecord::AddA {
            name: format!("before-wks.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.50".to_string(),
        },
        UpdateRecord::AddRecord {
            name: wks.clone(),
            rtype: Rtype::from_int(11),
            ttl: 300,
            rdata: vec![192, 0, 2, 1, 6, 0x40],
        },
    ];

    let before = app.list_records(&zone_name).await;
    let serial = app.read_zone_serial(&zone_name).await;

    for updates in [&replace, &retime, &wks_replace] {
        let rcode = send_update_udp(port, &zone_name, &[], updates, Some(&key)).expect("update");
        assert_eq!(rcode, Rcode::REFUSED, "{updates:?}");
        assert_eq!(app.list_records(&zone_name).await, before);
        assert_eq!(app.read_zone_serial(&zone_name).await, serial);
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

    for updates in [&replace, &retime, &wks_replace] {
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
async fn nsupdate_signed_prerequisite_requires_matching_grant() {
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

/// Verify that an unsigned update is NOTAUTH for an unserved zone and REFUSED
/// for a served one: authority before the signature policy (RFC 2136, Section 3.1.1).
#[tokio::test]
#[serial]
async fn nsupdate_checks_authority_before_refusing_unsigned_requests() {
    let app = TestApp::start_with_options(TestAppOptions {
        nsupdate_tsig_required: true,
        ..Default::default()
    })
    .await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let serial = app.read_zone_serial(zone_name).await;

    let unserved = app.zone_name("nsupdate-unsigned-notauth.example");
    let update = |zone: &str| {
        [UpdateRecord::AddA {
            name: format!("host.{zone}."),
            ttl: 300,
            addr: "192.0.2.71".to_string(),
        }]
    };

    assert_eq!(
        send_update_udp(app.dns_port(), &unserved, &[], &update(&unserved), None).unwrap(),
        Rcode::NOTAUTH
    );
    assert_eq!(
        send_update_udp(app.dns_port(), zone_name, &[], &update(zone_name), None).unwrap(),
        Rcode::REFUSED
    );
    assert_eq!(app.read_zone_serial(zone_name).await, serial);
}

/// Verify that prerequisites are evaluated in wire order (RFC 2136, Section
/// 3.2.5): the first failure answers before a later one is decoded.
#[tokio::test]
#[serial]
async fn nsupdate_evaluates_prerequisites_in_wire_order() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let absent = PrerequisiteRecord::NameInUse {
        name: format!("absent.{zone_name}."),
    };
    let outside = PrerequisiteRecord::RecordSetInUse {
        name: "outside.invalid.".to_string(),
        rtype: Rtype::A,
    };
    let update = [UpdateRecord::AddA {
        name: format!("host.{zone_name}."),
        ttl: 300,
        addr: "192.0.2.72".to_string(),
    }];

    for (prerequisites, rcode) in [
        (vec![absent.clone(), outside.clone()], Rcode::NXDOMAIN),
        (vec![outside, absent], Rcode::NOTZONE),
    ] {
        assert_eq!(
            send_update_udp(app.dns_port(), zone_name, &prerequisites, &update, None).unwrap(),
            rcode
        );
    }
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
async fn nsupdate_signs_parse_errors_with_request_key() {
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
async fn nsupdate_signs_badvers_with_request_key() {
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
async fn nsupdate_response_preserves_edns_dnssec_ok() {
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

/// Check derived names and RRsets for existence (RFC 2136, Sections 3.2.1–3.2.2).
#[tokio::test]
#[serial]
async fn dnssec_prerequisites_see_derived_records() {
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

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&signed=true&limit=1000"),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let before = app.list_records(zone_name).await;
    let serial = app.read_zone_serial(zone_name).await;

    let add = [UpdateRecord::AddA {
        name: format!("must-not-exist.{zone_name}."),
        ttl: 300,
        addr: "192.0.2.140".to_string(),
    }];
    let derived: Vec<_> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["id"].is_null())
        .collect();

    assert!(derived.iter().any(|row| row["type"] == "DNSKEY"));
    assert!(derived.iter().any(|row| row["type"] == "NSEC3"));

    for row in derived {
        let name = row["name"].as_str().unwrap().to_string();
        let rtype: Rtype = row["type"].as_str().unwrap().parse().unwrap();

        for (prerequisite, expected) in [
            (
                PrerequisiteRecord::RecordSetInUse {
                    name: name.clone(),
                    rtype,
                },
                Rcode::NOERROR,
            ),
            (
                PrerequisiteRecord::RecordSetNotInUse {
                    name: name.clone(),
                    rtype,
                },
                Rcode::YXRRSET,
            ),
            (
                PrerequisiteRecord::NameInUse { name: name.clone() },
                Rcode::NOERROR,
            ),
            (PrerequisiteRecord::NameNotInUse { name }, Rcode::YXDOMAIN),
        ] {
            let updates = if expected == Rcode::NOERROR {
                &[][..]
            } else {
                &add
            };
            let rcode = send_update_udp(app.dns_port(), zone_name, &[prerequisite], updates, None)
                .expect("prerequisite response");

            assert_eq!(rcode, expected, "{row}");
            assert_eq!(app.list_records(zone_name).await, before);
            assert_eq!(app.read_zone_serial(zone_name).await, serial);
        }
    }
}

/// Check RRset equality with NSEC/NSEC3 and split keys (RFC 2136, Section 3.2.3).
#[tokio::test]
#[serial]
async fn dnssec_prerequisites_compare_whole_served_record_sets() {
    for denial in ["nsec", "nsec3"] {
        let app = unsigned_nsupdate_app().await;
        let zone = app.create_test_zone().await;
        let zone_name = zone["name"].as_str().unwrap();

        // Exercise different stored encodings through the same wire comparison.
        for mut record in [
            json!({"name": "v6", "type": "AAAA", "value": "2001:db8::1"}),
            json!({"name": "txt", "type": "TXT", "value": "\"First\" \"second\""}),
            json!({"name": "mail", "type": "MX", "value": "Mail.Example.NET.", "priority": 10}),
            json!({"name": "alias", "type": "CNAME", "value": "Target.Example.NET."}),
            json!({"name": "caa", "type": "CAA", "value": "0 issue \"ca.example\""}),
        ] {
            record["zone_name"] = json!(zone_name);
            let (status, body) = app
                .send_request(Method::POST, "/records", Some(record))
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }

        let policy_name = format!("{}-prereq", app.namespace());

        let (status, body) = app
            .send_request(
                Method::POST,
                "/dnssec-policies",
                Some(json!({
                    "name": policy_name, "denial": denial, "split_keys": true,
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");

        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("/zones/{zone_name}/dnssec"),
                Some(json!({
                    "policy_name": policy_name, "parent_ns_addrs": ["127.0.0.1:9"],
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");

        let sets = fetch_exported_record_sets(&app, zone_name).await;

        let apex = format!("{zone_name}.");

        for rtype in [
            Rtype::DNSKEY,
            Rtype::RRSIG,
            Rtype::CDS,
            Rtype::CDNSKEY,
            Rtype::SOA,
            Rtype::NS,
        ] {
            assert!(
                sets.contains_key(&(apex.clone(), rtype)),
                "missing {rtype}: {sets:?}"
            );
        }

        let denial_type = if denial == "nsec" {
            Rtype::NSEC
        } else {
            Rtype::NSEC3
        };

        assert!(sets.keys().any(|(_, rtype)| *rtype == denial_type));
        assert!(sets[&(apex.clone(), Rtype::DNSKEY)].len() > 1);

        let serial = app.read_zone_serial(zone_name).await;

        for ((name, rtype), values) in &sets {
            let prerequisites: Vec<_> = values
                .iter()
                .map(|rdata| PrerequisiteRecord::RecordEquals {
                    name: name.clone(),
                    rtype: *rtype,
                    rdata: rdata.clone(),
                })
                .collect();
            let rcode = send_update_udp(app.dns_port(), zone_name, &prerequisites, &[], None)
                .expect("exact set");

            assert_eq!(rcode, Rcode::NOERROR, "{name} {rtype}");
            let mut repeated = prerequisites.clone();
            repeated.reverse();
            repeated.extend(prerequisites.clone());
            let rcode = send_update_udp(app.dns_port(), zone_name, &repeated, &[], None)
                .expect("repeated set");

            assert_eq!(rcode, Rcode::NOERROR, "{name} {rtype}");

            if prerequisites.len() > 1 {
                let rcode =
                    send_update_udp(app.dns_port(), zone_name, &prerequisites[..1], &[], None)
                        .expect("subset");
                assert_eq!(rcode, Rcode::NXRRSET, "{name} {rtype}");
            }
        }

        // A different DNSKEY remains well-formed but must fail equality.
        let values = &sets[&(apex.clone(), Rtype::DNSKEY)];
        let mut wrong = values.clone();
        *wrong[0].last_mut().unwrap() ^= 1;

        for values in [
            wrong.clone(),
            values.iter().chain(&wrong[..1]).cloned().collect(),
        ] {
            let prerequisites: Vec<_> = values
                .into_iter()
                .map(|rdata| PrerequisiteRecord::RecordEquals {
                    name: apex.clone(),
                    rtype: Rtype::DNSKEY,
                    rdata,
                })
                .collect();
            let rcode = send_update_udp(app.dns_port(), zone_name, &prerequisites, &[], None)
                .expect("different set");

            assert_eq!(rcode, Rcode::NXRRSET);
        }

        // Read-only checks must not advance the signed view.
        assert_eq!(app.read_zone_serial(zone_name).await, serial);
        assert_eq!(fetch_exported_record_sets(&app, zone_name).await, sets);

        // Re-signing must make the old RRSIG prerequisite fail.
        let signatures: Vec<_> = sets[&(apex.clone(), Rtype::RRSIG)]
            .iter()
            .map(|rdata| PrerequisiteRecord::RecordEquals {
                name: apex.clone(),
                rtype: Rtype::RRSIG,
                rdata: rdata.clone(),
            })
            .collect();
        let add = |owner: &str| UpdateRecord::AddA {
            name: format!("{owner}.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.141".to_string(),
        };
        let rcode = send_update_udp(
            app.dns_port(),
            zone_name,
            &signatures,
            &[add("accepted")],
            None,
        )
        .expect("guarded write");

        assert_eq!(rcode, Rcode::NOERROR);
        assert_eq!(app.read_zone_serial(zone_name).await, serial + 1);

        let after = fetch_exported_record_sets(&app, zone_name).await;

        assert_ne!(
            after[&(apex.clone(), Rtype::RRSIG)],
            sets[&(apex.clone(), Rtype::RRSIG)]
        );
        let rcode = send_update_udp(
            app.dns_port(),
            zone_name,
            &signatures,
            &[add("rejected")],
            None,
        )
        .expect("stale guard");

        assert_eq!(rcode, Rcode::NXRRSET);
        assert_eq!(app.read_zone_serial(zone_name).await, serial + 1);
        assert_eq!(fetch_exported_record_sets(&app, zone_name).await, after);
    }
}

/// Check derived read grants and signed TCP errors.
#[tokio::test]
#[serial]
async fn dnssec_prerequisites_require_read_grants_and_sign_errors() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({
                "parent_ns_addrs": ["127.0.0.1:9"],
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let key = create_tsig_key(&app, "dnssec-prereq", KeyRole::Own).await;
    app.run_cli_success(
        &[
            "role",
            "grant",
            &key.name,
            "--zone",
            zone_name,
            "--actions",
            "record:read",
            "--types",
            "A",
        ],
        None,
    )
    .await;

    let apex = format!("{zone_name}.");

    let sets = fetch_exported_record_sets(&app, zone_name).await;
    let values = &sets[&(apex.clone(), Rtype::DNSKEY)];
    let prerequisites: Vec<_> = values
        .iter()
        .map(|rdata| PrerequisiteRecord::RecordEquals {
            name: apex.clone(),
            rtype: Rtype::DNSKEY,
            rdata: rdata.clone(),
        })
        .collect();
    let rcode = send_update_tcp(app.dns_port(), zone_name, &prerequisites, &[], Some(&key))
        .expect("restricted read");

    assert_eq!(rcode, Rcode::REFUSED);

    app.run_cli_success(
        &[
            "role",
            "grant",
            &key.name,
            "--zone",
            zone_name,
            "--actions",
            "record:read",
        ],
        None,
    )
    .await;

    let rcode = send_update_tcp(app.dns_port(), zone_name, &prerequisites, &[], Some(&key))
        .expect("granted read");

    assert_eq!(rcode, Rcode::NOERROR);

    for (rtype, rdata, expected) in [
        (Rtype::DNSKEY, vec![1, 1, 3], Rcode::FORMERR),
        // RFC 2136, Section 3.2 restricts no type; an unstored one is absent.
        (Rtype::from_int(65280), vec![], Rcode::NXRRSET),
    ] {
        let prerequisite = PrerequisiteRecord::RecordEquals {
            name: apex.clone(),
            rtype,
            rdata,
        };
        let rcode = send_update_tcp(app.dns_port(), zone_name, &[prerequisite], &[], Some(&key))
            .expect("signed error");

        assert_eq!(rcode, expected);
    }

    assert_eq!(fetch_exported_record_sets(&app, zone_name).await, sets);
}

/// Preserve binary owners, TXT octets, WKS service bitmaps, and RDATA case.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn update_preserves_binary_values_and_names() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone = zone["name"].as_str().unwrap();

    let key = create_tsig_key(&app, "opaque-key", KeyRole::Admin).await;

    let target = crate::common::dns::parse_name("Mixed.Example.")
        .unwrap()
        .as_slice()
        .to_vec();

    for (label, rtype, rdata) in [
        (r"\255\032", Rtype::TXT, vec![1, 255, 1, 0]),
        ("split", Rtype::TXT, vec![1, 0xc3, 1, 0xa9]),
        ("wks", Rtype::WKS, vec![192, 0, 2, 1, 6, 0x80, 1]),
        (
            "srv",
            Rtype::SRV,
            [vec![0, 1, 0, 2, 0, 80], target.clone()].concat(),
        ),
        ("dname", Rtype::DNAME, target),
    ] {
        let owner = format!("{label}.{zone}.");
        let export_owner = format!("{}.", crate::common::dns::parse_name(&owner).unwrap());

        assert_eq!(
            send_update_udp(
                app.dns_port(),
                zone,
                &[],
                &[UpdateRecord::AddRecord {
                    name: owner.clone(),
                    rtype,
                    ttl: 300,
                    rdata: rdata.clone()
                }],
                Some(&key)
            )
            .unwrap(),
            Rcode::NOERROR
        );

        let exported = fetch_exported_record_sets(&app, zone).await;

        assert_eq!(
            exported.get(&(export_owner.clone(), rtype)).unwrap(),
            &vec![rdata.clone()]
        );
        assert_eq!(
            send_update_udp(
                app.dns_port(),
                zone,
                &[PrerequisiteRecord::RecordEquals {
                    name: owner.clone(),
                    rtype,
                    rdata: rdata.clone()
                }],
                &[UpdateRecord::DeleteRecord {
                    name: owner.clone(),
                    rtype,
                    rdata
                }],
                Some(&key)
            )
            .unwrap(),
            Rcode::NOERROR
        );
        assert!(
            !fetch_exported_record_sets(&app, zone)
                .await
                .contains_key(&(export_owner, rtype))
        );
    }
}

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
async fn soa_addition_ignores_ineffective_updates() {
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
        let rcode = send_update_udp(
            app.dns_port(),
            zone_name,
            &[],
            &[UpdateRecord::AddSoa {
                name,
                ttl: 600,
                soa: replacement(zone_name, serial),
            }],
            None,
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
        send_update_udp(
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
            ],
            None
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
                .filter(|record| record["type"] == "A")
                .count(),
            count
        );
    }

    let prerequisite = PrerequisiteRecord::SoaEquals {
        name: format!("{zone_name}."),
        soa: replacement(zone_name, serial + 20),
    };

    assert_eq!(
        send_update_udp(
            app.dns_port(),
            zone_name,
            &[prerequisite],
            &[add("next")],
            None
        )
        .unwrap(),
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
            .all(|record| record["type"] != "A")
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
    app.run_cli_success(
        &[
            "role",
            "grant",
            "soa-writer",
            "--zone",
            zone_name,
            "--actions",
            "record:create",
        ],
        None,
    )
    .await;
    let before = metadata(&app, zone_name).await;

    let updates = [UpdateRecord::AddSoa {
        name: format!("{zone_name}."),
        ttl: 600,
        soa: replacement(zone_name, 100),
    }];

    assert_eq!(
        send_update_tcp(app.dns_port(), zone_name, &[], &updates, Some(&key)).unwrap(),
        Rcode::REFUSED
    );
    assert_eq!(metadata(&app, zone_name).await, before);

    app.run_cli_success(
        &[
            "role",
            "grant",
            "soa-writer",
            "--zone",
            zone_name,
            "--actions",
            "zone:update",
        ],
        None,
    )
    .await;

    assert_eq!(
        send_update_tcp(app.dns_port(), zone_name, &[], &updates, Some(&key)).unwrap(),
        Rcode::NOERROR
    );
    assert_eq!(app.read_zone_serial(zone_name).await, 100);
}

/// Policy failures and failed prerequisites roll back SOA and ordinary records together.
#[tokio::test]
#[serial]
async fn soa_replacement_rejects_invalid_changes_atomically() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    assert_eq!(
        send_update_udp(
            app.dns_port(),
            zone_name,
            &[],
            &[UpdateRecord::AddDname {
                name: format!("blocked.{zone_name}."),
                ttl: 300,
                target: "target.example.net.".to_string(),
            }],
            None
        )
        .unwrap(),
        Rcode::NOERROR
    );

    let before = metadata(&app, zone_name).await;
    let records = app.list_records(zone_name).await;

    for (ttl, soa) in [
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
            send_update_udp(app.dns_port(), zone_name, &[], &updates, None).unwrap(),
            Rcode::REFUSED
        );
        assert_eq!(metadata(&app, zone_name).await, before);
        assert_eq!(app.list_records(zone_name).await, records);
    }

    let prerequisites = [PrerequisiteRecord::NameInUse {
        name: format!("absent.{zone_name}."),
    }];
    let updates = [UpdateRecord::AddSoa {
        name: format!("{zone_name}."),
        ttl: 600,
        soa: replacement(zone_name, 100),
    }];

    assert_eq!(
        send_update_udp(app.dns_port(), zone_name, &prerequisites, &updates, None).unwrap(),
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
        send_update_udp(app.dns_port(), zone_name, &[], &updates, None).unwrap(),
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
async fn soa_noop_accepts_maximum_serial() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for serial in [i32::MAX as u32, i32::MAX as u32, i32::MAX as u32 - 1] {
        assert_eq!(
            send_update_udp(
                app.dns_port(),
                zone_name,
                &[],
                &[UpdateRecord::AddSoa {
                    name: format!("{zone_name}."),
                    ttl: 600,
                    soa: replacement(zone_name, serial)
                }],
                None
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

    let before = fetch_exported_record_sets(&app, zone_name).await;

    let soa = replacement(zone_name, 100);

    assert_eq!(
        send_update_udp(
            app.dns_port(),
            zone_name,
            &[],
            &[UpdateRecord::AddSoa {
                name: format!("{zone_name}."),
                ttl: 900,
                soa: soa.clone()
            }],
            None
        )
        .unwrap(),
        Rcode::NOERROR
    );

    let after = fetch_exported_record_sets(&app, zone_name).await;

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
    let prerequisites = [PrerequisiteRecord::SoaEquals {
        name: format!("{zone_name}."),
        soa,
    }];

    assert_eq!(
        send_update_udp(app.dns_port(), zone_name, &prerequisites, &[], None).unwrap(),
        Rcode::NOERROR
    );
    assert_eq!(app.read_zone_serial(zone_name).await, 100);
}

/// Transfer the old and new SOAs around one delta even when the serial skips values.
#[tokio::test]
#[serial]
async fn ixfr_replays_soa_replacement() {
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
        send_update_udp(app.dns_port(), zone_name, &[], &padding, None).unwrap(),
        Rcode::NOERROR
    );

    let old_serial = u32::try_from(app.read_zone_serial(zone_name).await).unwrap();
    let before = fetch_exported_record_sets(&app, zone_name).await;

    let soa = replacement(zone_name, old_serial + 10);

    assert_eq!(
        send_update_udp(
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
            ],
            None
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

/// Reusing a wire serial after a full cycle cannot resurrect old transfer content or history.
#[tokio::test]
#[serial]
async fn soa_serial_reuse_refreshes_the_transfer_cache() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let initial = u32::try_from(app.read_zone_serial(zone_name).await).unwrap();
    let key = create_tsig_key(&app, "serial-reuse", KeyRole::Admin).await;
    let before = crate::common::axfr(app.dns_port(), zone_name, Some(&key))
        .unwrap()
        .records();

    for (index, serial) in [
        initial.wrapping_add(0x7fff_ffff),
        initial.wrapping_sub(2),
        initial,
    ]
    .into_iter()
    .enumerate()
    {
        let mut updates = vec![UpdateRecord::AddSoa {
            name: format!("{zone_name}."),
            ttl: 600,
            soa: replacement(zone_name, serial),
        }];

        if index == 0 {
            updates.push(UpdateRecord::AddA {
                name: format!("new.{zone_name}."),
                ttl: 300,
                addr: "192.0.2.99".into(),
            });
        }

        assert_eq!(
            send_update_udp(app.dns_port(), zone_name, &[], &updates, Some(&key)).unwrap(),
            Rcode::NOERROR
        );
    }

    assert_eq!(app.read_zone_serial(zone_name).await, i64::from(initial));
    assert_eq!(
        crate::common::axfr(app.dns_port(), zone_name, Some(&key))
            .unwrap()
            .records(),
        before + 1
    );

    let (_, history) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/versions"), None)
        .await;

    assert_eq!(history["items"].as_array().unwrap().len(), 2, "{history}");

    // RFC 2136, Section 3.6 still requires an increment if one atomic request
    // traverses the whole circle and finishes with the original serial.
    let updates: Vec<_> = [
        initial.wrapping_add(0x7fff_ffff),
        initial.wrapping_sub(2),
        initial,
    ]
    .into_iter()
    .map(|serial| UpdateRecord::AddSoa {
        name: format!("{zone_name}."),
        ttl: 600,
        soa: replacement(zone_name, serial),
    })
    .collect();

    assert_eq!(
        send_update_udp(app.dns_port(), zone_name, &[], &updates, Some(&key)).unwrap(),
        Rcode::NOERROR
    );
    assert_eq!(
        app.read_zone_serial(zone_name).await,
        i64::from(initial.wrapping_add(1))
    );
}

/// Start a local daemon accepting unsigned DNS updates.
async fn unsigned_nsupdate_app() -> TestApp {
    TestApp::start_with_options(TestAppOptions {
        nsupdate_tsig_required: false,
        ..TestAppOptions::default()
    })
    .await
}

/// A policy-refused ordinary type rolls back every operation in the request.
#[tokio::test]
#[serial]
async fn nsupdate_rejects_unsupported_types_and_invalid_wks_atomically() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let before = app.list_records(zone_name).await;
    let serial = app.read_zone_serial(zone_name).await;

    for (rtype, rdata, expected) in [
        (Rtype::HINFO, vec![0, 0], Rcode::FORMERR),
        (Rtype::from_int(65280), vec![0, 0], Rcode::FORMERR),
        (Rtype::WKS, vec![192, 0, 2, 1, 6, 0x80, 0], Rcode::FORMERR),
    ] {
        let updates = [
            UpdateRecord::AddA {
                name: format!("before.{zone_name}."),
                ttl: 300,
                addr: "192.0.2.1".into(),
            },
            UpdateRecord::AddRecord {
                name: format!("unsupported.{zone_name}."),
                rtype,
                ttl: 300,
                rdata,
            },
        ];

        for rcode in [
            send_update_udp(app.dns_port(), zone_name, &[], &updates, None).unwrap(),
            send_update_tcp(app.dns_port(), zone_name, &[], &updates, None).unwrap(),
        ] {
            assert_eq!(rcode, expected);
        }

        assert_eq!(app.list_records(zone_name).await, before);
        assert_eq!(app.read_zone_serial(zone_name).await, serial);
    }
}

/// UPDATE preserves high-bit TTLs and replaces only a WKS address/protocol match.
#[tokio::test]
#[serial]
async fn nsupdate_replaces_wks_by_address_and_protocol() {
    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let owner = format!("wks.{zone_name}.");
    let rtype = Rtype::from_int(11);
    let original = vec![192, 0, 2, 1, 6, 0x80];
    let replacement = vec![192, 0, 2, 1, 6, 0x40];
    let other_address = vec![192, 0, 2, 2, 6, 0x80];
    let other_protocol = vec![192, 0, 2, 1, 17, 0x80];

    for rdata in [&original, &other_address, &other_protocol, &replacement] {
        let serial = app.read_zone_serial(zone_name).await;

        let rcode = send_update_tcp(
            app.dns_port(),
            zone_name,
            &[],
            &[UpdateRecord::AddRecord {
                name: owner.clone(),
                rtype,
                ttl: u32::MAX,
                rdata: rdata.clone(),
            }],
            None,
        )
        .unwrap();

        assert_eq!(rcode, Rcode::NOERROR);
        assert_eq!(app.read_zone_serial(zone_name).await, serial + 1);
    }

    let serial = app.read_zone_serial(zone_name).await;

    let rcode = send_update_tcp(
        app.dns_port(),
        zone_name,
        &[],
        &[UpdateRecord::AddRecord {
            name: owner.clone(),
            rtype,
            ttl: u32::MAX,
            rdata: replacement.clone(),
        }],
        None,
    )
    .unwrap();

    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(app.read_zone_serial(zone_name).await, serial);

    let sets = fetch_exported_record_sets(&app, zone_name).await;
    let mut actual = sets.get(&(owner, rtype)).unwrap().clone();
    actual.sort();
    let mut expected = vec![replacement, other_address, other_protocol];
    expected.sort();

    assert_eq!(actual, expected);
    assert!(
        app.list_records(zone_name)
            .await
            .iter()
            .filter(|row| row["type"] == "WKS")
            .all(|row| row["ttl"] == u32::MAX)
    );
}

/// Reply to pipelined UPDATEs after a TCP write-half close.
#[tokio::test]
#[serial]
async fn nsupdate_answers_pipelined_requests_after_write_half_close() {
    use std::net::{Shutdown, TcpStream};

    use crate::common::dns::{read_frame, write_frame};

    let app = unsigned_nsupdate_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", app.dns_port())).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    for id in [81, 82] {
        let request = build_update(
            id,
            zone_name,
            Class::IN,
            &[],
            &[UpdateRecord::AddA {
                name: format!("half{id}.{zone_name}."),
                ttl: u32::MAX,
                addr: "192.0.2.5".to_string(),
            }],
        )
        .unwrap()
        .finish();
        write_frame(&mut stream, &request).unwrap();
    }

    stream.shutdown(Shutdown::Write).unwrap();
    let mut ids = Vec::new();

    for _ in 0..2 {
        let response = Message::from_octets(read_frame(&mut stream).unwrap().unwrap()).unwrap();
        assert_eq!(response.header().rcode(), Rcode::NOERROR);
        ids.push(response.header().id());
    }

    ids.sort();

    assert_eq!(ids, [81, 82]);
}

/// Accept an advancing SOA carrying an already accepted non-UTF-8 mailbox domain.
#[tokio::test]
#[serial]
async fn soa_replacement_preserves_mailbox_domain_octets() {
    let app = TestApp::start_with_options(TestAppOptions {
        nsupdate_tsig_required: false,
        ..Default::default()
    })
    .await;
    let name = app.zone_name("octet-soa.example");

    let (status, body) = app.send_request(Method::POST, "/zones", Some(json!({
        "name": name, "mname": "ns.example.com", "rname": r"admin@\255.example.com", "serial": 1
    }))).await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let signing_key = create_tsig_key(&app, "octet-soa-key", KeyRole::Admin).await;

    let mut serial = 1;

    for key in [None, Some(&signing_key)] {
        serial += 1;
        let soa = Soa::new(
            parse_name("ns.example.com").unwrap(),
            parse_name(r"admin.\255.example.com").unwrap(),
            serial.into(),
            Ttl::from_secs(300),
            Ttl::from_secs(60),
            Ttl::from_secs(86400),
            Ttl::ZERO,
        );
        let updates = [UpdateRecord::AddSoa {
            name: name.clone(),
            ttl: 300,
            soa,
        }];

        assert_eq!(
            send_update_udp(app.dns_port(), &name, &[], &updates, key).unwrap(),
            Rcode::NOERROR
        );
        serial += 1;
        let soa = Soa::new(
            parse_name("ns.example.com").unwrap(),
            parse_name(r"admin.\255.example.com").unwrap(),
            serial.into(),
            Ttl::from_secs(300),
            Ttl::from_secs(60),
            Ttl::from_secs(86400),
            Ttl::ZERO,
        );
        let updates = [UpdateRecord::AddSoa {
            name: name.clone(),
            ttl: 300,
            soa,
        }];

        assert_eq!(
            send_update_tcp(app.dns_port(), &name, &[], &updates, key).unwrap(),
            Rcode::NOERROR
        );
        assert_eq!(app.read_zone_serial(&name).await, i64::from(serial));
    }

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{name}"), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["rname"], r"admin@\255.example.com");
}
