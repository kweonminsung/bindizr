//! Zone transfers over TLS require both TSIG and address authorization
//! without mTLS (RFC 9103, Section 7.5).

use std::io;

use base64::engine::general_purpose;
use domain::base::iana::{Class, ExtendedErrorCode, Opcode, OptRcode, Rcode, Rtype, TsigRcode};
use domain::base::message_builder::AdditionalBuilder;
use domain::base::opt::exterr::ExtendedError;
use domain::base::{Message, MessageBuilder};
use domain::rdata::tsig::{Time48, Tsig};
use domain::rdata::{Dnskey, Rrsig, Soa};
use domain::tsig::{Algorithm, ClientSequence, ClientTransaction, Key, KeyName};
use reqwest::{Method, StatusCode};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use rustls::version;
use serde_json::json;

use crate::common::dns::nsupdate::UpdateRecord;
use crate::common::dns::tsig::KeyRole;
use crate::common::dns::{nsupdate, tsig};
use crate::common::{TestApp, TestAppOptions, dns};
use crate::xfr::common;

/// Start a bindizr serving XoT beside plain TCP.
async fn xot_app() -> TestApp {
    TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await
}

/// Finish a signed transfer, verifying every frame and its closing signature.
fn exchange_signed_boundary_transfer<S: io::Read + io::Write>(
    stream: &mut S,
    mut query: AdditionalBuilder<Vec<u8>>,
    key: Key,
) -> Vec<Message<Vec<u8>>> {
    let mut client = ClientSequence::request(key, &mut query, Time48::now()).unwrap();
    dns::write_frame(stream, &query.finish()).unwrap();
    let mut messages = Vec::new();
    let mut soa_count = 0;

    while soa_count < 2 {
        let response = dns::read_frame(stream).unwrap().expect("closing SOA");
        let mut response = Message::from_octets(response).unwrap();

        assert_eq!(response.header().rcode(), Rcode::NOERROR);
        client.answer(&mut response, Time48::now()).unwrap();
        soa_count += response
            .answer()
            .unwrap()
            .map(Result::unwrap)
            .filter(|record| record.rtype() == Rtype::SOA)
            .count();
        messages.push(response);
    }

    client.done().unwrap();

    messages
}

/// Verify that maximum storable RDATA fits SHA-512-signed EDNS AXFR over TCP and TLS.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn maximum_record_value_transfers_with_signed_edns_and_long_names() {
    use std::str::FromStr;

    use base64::Engine;

    let app = xot_app().await;
    app.create_secondary("boundary-loopback", "127.0.0.1:9")
        .await;

    let longest_name = |labels: [char; 4]| {
        labels
            .into_iter()
            .zip([63, 63, 63, 61])
            .map(|(ch, len)| ch.to_string().repeat(len))
            .collect::<Vec<_>>()
            .join(".")
    };
    let zone_name = longest_name(['a', 'b', 'c', 'd']);
    let tsig_key_name = longest_name(['k', 'l', 'm', 'n']);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name, "mname": "ns.example", "rname": "admin@example.com"
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({
                "name": tsig_key_name, "algorithm": "hmac-sha512", "role_name": "admin"
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    let secret = general_purpose::STANDARD
        .decode(body["secret"].as_str().unwrap())
        .unwrap();
    let key = Key::new(
        Algorithm::Sha512,
        &secret,
        KeyName::from_str(&tsig_key_name).unwrap(),
        None,
        None,
    )
    .unwrap();

    // 64,618 wire bytes leave room for maximal names, TSIG, OPT and keepalive.
    let value = format!("3 0 0 {}", "AB".repeat(64618 - 3));

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "zone_name": zone_name, "name": "@", "type": "TLSA", "value": value, "ttl": 300
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let base_serial = app.read_zone_serial(&zone_name).await;

    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "zone_name": zone_name, "name": "@", "type": "TLSA",
                "value": format!("{value}AB"), "ttl": 300
            })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(app.read_zone_serial(&zone_name).await, base_serial);

    let plain = exchange_signed_boundary_transfer(
        &mut dns::connect_tcp(app.dns_port()).unwrap(),
        common::build_edns_query(&zone_name, Rtype::AXFR, &[(0, false)]),
        key.clone(),
    );
    let tls = exchange_signed_boundary_transfer(
        &mut dns::connect_tls(app.dns_tls_port(), common::dot_client(&app)).unwrap(),
        common::build_edns_query(&zone_name, Rtype::AXFR, &[(0, false)]),
        key,
    );

    for messages in [plain, tls] {
        assert!(messages.len() >= 2);
        let mut types = Vec::new();

        for message in messages {
            assert_eq!(message.header().id(), 3225);
            assert!(!message.header().tc());
            assert!(message.opt().unwrap().opt().tcp_keepalive().is_some());

            for record in message.answer().unwrap().map(Result::unwrap) {
                types.push(record.rtype());
                if record.rtype() == Rtype::TLSA {
                    assert_eq!(record.rdlen(), 64618);
                }
            }
        }

        assert_eq!(types.first(), Some(&Rtype::SOA));
        assert_eq!(types.last(), Some(&Rtype::SOA));
        assert_eq!(
            types.iter().filter(|&&rtype| rtype == Rtype::SOA).count(),
            2
        );
        assert_eq!(
            types.iter().filter(|&&rtype| rtype == Rtype::TLSA).count(),
            1
        );
    }
}

/// Verify that SOA replies carry verifiable RRSIGs only with DO and that IXFR stays SOA-only.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn soa_queries_return_current_signatures_when_dnssec_is_requested() {
    use domain::base::ToName;
    use domain::base::rdata::ComposeRecordData;

    let app = xot_app().await;
    app.create_secondary("loopback", "127.0.0.1:9").await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "soa-signature-key", KeyRole::Admin).await;

    for stage in 0..3 {
        if stage == 1 {
            let (status, _) = app
                .send_request(
                    Method::POST,
                    &format!("/zones/{zone_name}/dnssec"),
                    Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"] })),
                )
                .await;

            assert_eq!(status, StatusCode::CREATED);
        } else if stage == 2 {
            let (status, _) = app
                .send_request(
                    Method::POST,
                    "/records",
                    Some(json!({
                        "zone_name": zone_name, "name": "new", "type": "A", "value": "192.0.2.1", "ttl": 3600
                    })),
                )
                .await;

            assert_eq!(status, StatusCode::CREATED);
        }

        let current_serial = u32::try_from(app.read_zone_serial(zone_name).await).unwrap();

        let transfer = dns::exchange_request(
            common::build_edns_query(zone_name, Rtype::AXFR, &[]),
            Some(&key),
            |message| dns::exchange_tcp(app.dns_port(), message),
        )
        .unwrap();
        let public = transfer
            .answer()
            .unwrap()
            .limit_to::<Dnskey<_>>()
            .next()
            .map(|record| record.unwrap().data().public_key().to_vec());

        for dnssec_ok in [false, true] {
            for signed in [false, true] {
                for transport in ["udp", "tcp", "tls"] {
                    let signer = if signed || transport == "tls" {
                        Some(&key)
                    } else {
                        None
                    };
                    let response = dns::exchange_request(
                        common::build_edns_query(zone_name, Rtype::SOA, &[(0, dnssec_ok)]),
                        signer,
                        |message| match transport {
                            "udp" => dns::exchange_udp(app.dns_port(), message),
                            "tcp" => dns::exchange_tcp(app.dns_port(), message),
                            _ => dns::exchange_tls(
                                app.dns_tls_port(),
                                message,
                                common::dot_client(&app),
                            ),
                        },
                    )
                    .unwrap();

                    assert!(!response.header().tc());
                    let soa = response
                        .answer()
                        .unwrap()
                        .limit_to::<Soa<_>>()
                        .next()
                        .unwrap()
                        .unwrap();

                    assert_eq!(soa.data().serial().into_int(), current_serial);
                    let signatures = response
                        .answer()
                        .unwrap()
                        .limit_to::<Rrsig<_, _>>()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();

                    assert_eq!(signatures.len(), usize::from(stage > 0 && dnssec_ok));

                    for signature in signatures {
                        let data = signature.data();

                        assert_eq!(data.type_covered(), Rtype::SOA);
                        let mut signed_data = Vec::new();
                        data.compose_canonical_rdata(&mut signed_data).unwrap();
                        signed_data.truncate(signed_data.len() - data.signature().len());
                        soa.owner().compose_canonical(&mut signed_data).unwrap();
                        signed_data.extend_from_slice(&Rtype::SOA.to_int().to_be_bytes());
                        signed_data.extend_from_slice(&Class::IN.to_int().to_be_bytes());
                        signed_data.extend_from_slice(&data.original_ttl().as_secs().to_be_bytes());
                        let mut rdata = Vec::new();
                        soa.data().compose_canonical_rdata(&mut rdata).unwrap();
                        signed_data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                        signed_data.extend_from_slice(&rdata);
                        let mut point = vec![4];
                        point.extend_from_slice(public.as_ref().unwrap());
                        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                            .verify(&signed_data, data.signature())
                            .unwrap();
                    }
                }
            }
        }

        let response = dns::exchange_request(
            common::build_edns_query(zone_name, Rtype::IXFR, &[(0, true)]),
            Some(&key),
            |message| dns::exchange_udp(app.dns_port(), message),
        )
        .unwrap();

        assert_eq!(response.header_counts().ancount(), 1);

        if stage == 2 {
            let long_tsig_key_name = format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61)
            );

            let long_key = tsig::create_tsig_key(&app, &long_tsig_key_name, KeyRole::Admin).await;

            for tcp in [false, true] {
                let mut question = MessageBuilder::new_vec().question();
                question
                    .push((&dns::parse_name(zone_name).unwrap(), Rtype::SOA))
                    .unwrap();
                let mut query = question.additional();
                query
                    .opt(|opt| {
                        opt.set_udp_payload_size(512);
                        opt.set_dnssec_ok(true);
                        Ok(())
                    })
                    .unwrap();
                let response = dns::exchange_request(query, Some(&long_key), |message| {
                    if tcp {
                        dns::exchange_tcp(app.dns_port(), message)
                    } else {
                        dns::exchange_udp(app.dns_port(), message)
                    }
                })
                .unwrap();

                assert_eq!(response.header().tc(), !tcp);
                assert!(response.opt().unwrap().dnssec_ok());

                if tcp {
                    assert_eq!(response.header_counts().ancount(), 2);
                } else {
                    assert_eq!(response.header_counts().ancount(), 0);
                    assert!(response.as_slice().len() <= 512);
                }
            }
        }
    }
}

/// Verify that TLS requires both key and address authorization while plain accepts either.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tls_transfer_requires_key_and_registered_address() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "xot-key", KeyRole::Admin).await;

    // RFC 9103, Section 7.5: TLS requires both key and address authorization.
    let outcome = dns::fetch_axfr_tls(
        app.dns_tls_port(),
        zone_name,
        Some(&key),
        common::dot_client(&app),
    )
    .expect("XoT");

    assert_eq!(outcome.refusal(), Rcode::REFUSED);

    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, Some(&key)).expect("AXFR");

    assert!(outcome.records() >= 3);

    // The address alone is refused over TLS as well.
    app.create_secondary("loopback", "127.0.0.1").await;

    let outcome = dns::fetch_axfr_tls(
        app.dns_tls_port(),
        zone_name,
        None,
        common::dot_client(&app),
    )
    .expect("XoT");

    assert_eq!(outcome.refusal(), Rcode::REFUSED);

    // Both together: served, every envelope verified under the key.
    let outcome = dns::fetch_axfr_tls(
        app.dns_tls_port(),
        zone_name,
        Some(&key),
        common::dot_client(&app),
    )
    .expect("XoT");

    assert!(outcome.records() >= 3);

    // The transfer log and the metric say which transport served each one.
    let (status, body) = app
        .send_request(Method::GET, "/logs/transfer?secondary_name=loopback", None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"][0]["transport"], "tls", "{body}");

    let tls_ok = common::read_counter(
        &app,
        "bindizr_xfr_total",
        &[r#"type="axfr""#, r#"result="ok""#, r#"transport="tls""#],
    )
    .await;
    let tcp_ok = common::read_counter(
        &app,
        "bindizr_xfr_total",
        &[r#"type="axfr""#, r#"result="ok""#, r#"transport="tcp""#],
    )
    .await;

    assert_eq!(tls_ok, 1.0);
    assert_eq!(tcp_ok, 1.0);
}

/// Verify that IXFR serial policy applies over TLS after both transfer gates pass.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn ixfr_serial_policy_requires_a_key_and_registered_address() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let key = tsig::create_tsig_key(&app, "xot-ixfr-key", KeyRole::Admin).await;

    let current = u32::try_from(zone["serial"].as_u64().unwrap()).unwrap();

    for registered in [false, true] {
        if registered {
            app.create_secondary("loopback", "127.0.0.1").await;
        }

        for zone_name in [zone["name"].as_str().unwrap(), "catalog.bindizr"] {
            let expected = if registered {
                let query = common::build_edns_query(zone_name, Rtype::SOA, &[]);
                let response = dns::exchange_request(query, Some(&key), |message| {
                    dns::exchange_tls(app.dns_tls_port(), message, common::dot_client(&app))
                })
                .unwrap();

                response
                    .answer()
                    .unwrap()
                    .limit_to::<Soa<_>>()
                    .next()
                    .unwrap()
                    .unwrap()
                    .data()
                    .serial()
                    .into_int()
            } else {
                current
            };

            for serial in [expected, expected.wrapping_add(1)] {
                let query = common::build_ixfr_query(zone_name, serial);
                let response = dns::exchange_request(query, Some(&key), |message| {
                    dns::exchange_tls(app.dns_tls_port(), message, common::dot_client(&app))
                })
                .unwrap();

                if registered {
                    assert_eq!(response.header().rcode(), Rcode::NOERROR);
                    assert!(response.header().aa() && !response.header().tc());
                    assert_eq!(response.sole_question().unwrap().qtype(), Rtype::IXFR);
                    assert_eq!(response.header_counts().ancount(), 1);
                    let soa = response
                        .answer()
                        .unwrap()
                        .limit_to::<Soa<_>>()
                        .next()
                        .unwrap()
                        .unwrap();

                    assert_eq!(soa.data().serial().into_int(), expected);
                } else {
                    assert_eq!(response.header().rcode(), Rcode::REFUSED);
                    assert_eq!(response.header_counts().ancount(), 0);
                }
            }
        }
    }
}

/// Verify that DO is echoed in signed TLS responses, including REFUSED and BADVERS.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tls_response_preserves_edns_dnssec_ok() {
    let app = xot_app().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "xot-dnssec-ok-key", KeyRole::Admin).await;

    for dnssec_ok in [false, true] {
        for version in [0, 1] {
            for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR, Rtype::A] {
                let query = common::build_edns_query(zone_name, qtype, &[(version, dnssec_ok)]);
                let response = dns::exchange_request(query, Some(&key), |message| {
                    dns::exchange_tls(app.dns_tls_port(), message, common::dot_client(&app))
                })
                .unwrap();
                let opt = response.opt().unwrap();

                assert_eq!(opt.dnssec_ok(), dnssec_ok);
                let expected = if version != 0 {
                    OptRcode::BADVERS
                } else if qtype == Rtype::A {
                    OptRcode::REFUSED
                } else {
                    OptRcode::NOERROR
                };

                assert_eq!(opt.rcode(response.header()), expected);
                assert!(opt.opt().tcp_keepalive().is_some());
            }
        }
    }
}

/// Verify that stale TLS queries receive an authenticated BADTIME with OPT.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn badtime_tls_responses_preserve_edns_and_verify() {
    let app = xot_app().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "badtime-tls-key", KeyRole::Admin).await;

    let signed_at = Time48::from_u64(u64::from(Time48::now()) - 3600);

    for dnssec_ok in [false, true] {
        for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR] {
            let mut query = common::build_edns_query(zone_name, qtype, &[(0, dnssec_ok)]);
            ClientTransaction::request_with_fudge(
                key.to_tsig_key().unwrap(),
                &mut query,
                signed_at,
                17,
            )
            .unwrap();
            let query = query.finish();
            let response =
                dns::exchange_tls(app.dns_tls_port(), &query, common::dot_client(&app)).unwrap();
            let response = Message::from_octets(response).unwrap();

            assert_eq!(response.header().id(), 3225);
            assert!(response.header().qr());
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
            tsig::verify_response_mac(&query, &response, &key).unwrap();
        }
    }
}

/// Verify that truncated TLS queries are authenticated before time and length policy applies.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn truncated_tls_queries_follow_tsig_validation_order() {
    let app = xot_app().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "truncated-tls-key", KeyRole::Admin).await;

    for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR] {
        for (age, corrupt, expected) in [
            (0, false, TsigRcode::BADTRUNC),
            (3600, false, TsigRcode::BADTIME),
            (0, true, TsigRcode::BADSIG),
            (3600, true, TsigRcode::BADSIG),
        ] {
            let signed_at = Time48::from_u64(u64::from(Time48::now()) - age);
            let mut query = common::build_edns_query(zone_name, qtype, &[(0, true)]);
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

            let response =
                dns::exchange_tls(app.dns_tls_port(), &query, common::dot_client(&app)).unwrap();
            let response = Message::from_octets(response).unwrap();

            assert_eq!(response.header().id(), 3225);
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
                tsig::verify_response_mac(&query, &response, &key).unwrap();
            }

            assert_eq!(
                tsig.data().other().len(),
                if expected == TsigRcode::BADTIME {
                    6
                } else {
                    0
                }
            );
        }
    }
}

/// Verify that multi-question queries over TLS receive signed FORMERR responses.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn multi_question_queries_receive_signed_formerr() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "xot-multi-question-key", KeyRole::Admin).await;

    for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR] {
        let query = common::build_multi_question_query(zone_name, qtype, Class::IN, Some(0));
        let response = dns::exchange_request(query, Some(&key), |message| {
            dns::exchange_tls(app.dns_tls_port(), message, common::dot_client(&app))
        })
        .unwrap();

        assert_eq!(response.header().rcode(), Rcode::FORMERR);
        assert_eq!(response.header().id(), 9619);
        assert!(response.header().qr() && response.header().rd());
        assert!(!response.header().aa() && !response.header().tc());
        assert_eq!(response.header_counts().ancount(), 0);
        assert_eq!(response.header_counts().nscount(), 0);
        assert_eq!(response.sole_question().unwrap().qtype(), qtype);
        assert!(response.opt().unwrap().dnssec_ok());
    }

    let mut unreadable =
        common::build_multi_question_query(zone_name, Rtype::SOA, Class::IN, None).finish();
    unreadable.truncate(12);
    let response =
        dns::exchange_tls(app.dns_tls_port(), &unreadable, common::dot_client(&app)).unwrap();
    let response = Message::from_octets(response).unwrap();

    assert_eq!(response.header().rcode(), Rcode::FORMERR);
    assert_eq!(response.header().id(), 9619);
    assert_eq!(response.header_counts().qdcount(), 0);
    assert_eq!(response.header_counts().ancount(), 0);
}

/// Verify that `require_tls` refuses plain transfers while allowing SOA and TLS (RFC 9103,
/// Section 11).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn require_tls_rejects_a_transfer_over_plain_tcp() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        dns_transfer_require_tls: true,
        ..Default::default()
    })
    .await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "xot-only-key", KeyRole::Admin).await;
    app.create_secondary("loopback", "127.0.0.1").await;

    // RFC 8945, Section 5.3: the refusal of a signed request is signed.
    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, Some(&key)).expect("AXFR");

    assert_eq!(outcome.refusal(), Rcode::REFUSED);
    assert!(outcome.refusal_signed());

    // A UDP IXFR is a transfer request too; a SOA query keeps answering.
    let response = dns::exchange_udp(
        app.dns_port(),
        &common::build_edns_query(zone_name, Rtype::IXFR, &[(0, false)]).finish(),
    )
    .unwrap();
    let response = Message::from_octets(response).unwrap();

    assert_eq!(response.header().rcode(), Rcode::REFUSED);
    assert_eq!(
        dns::probe_zone_soa(app.dns_port(), zone_name),
        Ok(Rcode::NOERROR)
    );

    let body =
        common::wait_for_transfer_log(&app, "secondary_name=loopback&result=refused", 1).await;
    let refused = &body["items"][0];

    assert_eq!(refused["result"], "refused", "{body}");
    assert_eq!(refused["transport"], "tcp", "{body}");
    assert!(
        refused["error"].as_str().unwrap().contains("require TLS"),
        "{body}"
    );

    let outcome = dns::fetch_axfr_tls(
        app.dns_tls_port(),
        zone_name,
        Some(&key),
        common::dot_client(&app),
    )
    .expect("XoT");

    assert!(outcome.records() >= 3);
}

/// Verify that `config reload` serves renewed certificates without a restart.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn config_reload_replaces_dns_tls_certificate() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "renewal-key", KeyRole::Admin).await;
    app.create_secondary("loopback", "127.0.0.1").await;

    let outcome = dns::fetch_axfr_tls(
        app.dns_tls_port(),
        zone_name,
        Some(&key),
        common::dot_client(&app),
    )
    .expect("XoT");

    assert!(outcome.records() >= 3);

    let renewed = app.renew_test_certificate();

    let reloaded = app.run_cli_success(&["config", "reload"], None).await;

    assert!(reloaded.contains("dns.tls certificate"), "{reloaded}");

    let client = common::xot_client(&renewed, &[&version::TLS13], &[b"dot"]);
    let outcome =
        dns::fetch_axfr_tls(app.dns_tls_port(), zone_name, Some(&key), client).expect("XoT");

    assert!(outcome.records() >= 3);

    // The renewed certificate has the same name; the old root must fail signature validation.
    let error = dns::fetch_axfr_tls(
        app.dns_tls_port(),
        zone_name,
        Some(&key),
        common::dot_client(&app),
    )
    .unwrap_err();

    assert!(error.contains("invalid peer certificate"), "{error}");

    // A bad certificate pair rejects reload and preserves the serving pair.
    app.corrupt_test_certificate();

    let args = ["config", "reload"];

    let refused = app.run_cli(&args, None).await;
    crate::common::assert_cli_failure_contains(&args, &refused, "nothing was reloaded");

    let client = common::xot_client(&renewed, &[&version::TLS13], &[b"dot"]);
    let outcome =
        dns::fetch_axfr_tls(app.dns_tls_port(), zone_name, Some(&key), client).expect("XoT");

    assert!(outcome.records() >= 3);
}

/// Verify that TLS 1.2 and ALPN without "dot" are rejected, including missing ALPN.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tls_handshake_rejects_tls_1_2_and_foreign_alpn() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (port, cert) = (app.dns_tls_port(), app.tls_cert());

    // RFC 9103, Section 7.2: TLS 1.3 or later only.
    let client = common::xot_client(cert, &[&version::TLS12], &[b"dot"]);
    let error = dns::fetch_axfr_tls(port, zone_name, None, client).unwrap_err();

    assert!(error.contains("ProtocolVersion"), "{error}");

    // RFC 9103, Section 7.1: negotiate only "dot" ALPN.
    let client = common::xot_client(cert, &[&version::TLS13], &[b"h2"]);
    let error = dns::fetch_axfr_tls(port, zone_name, None, client).unwrap_err();

    assert!(error.contains("NoApplicationProtocol"), "{error}");

    // Missing ALPN permits the handshake but closes the session before any answer.
    let client = common::xot_client(cert, &[&version::TLS13], &[]);
    let error = dns::fetch_axfr_tls(port, zone_name, None, client).unwrap_err();

    assert!(
        error.contains("without its closing SOA") || error.contains("close_notify"),
        "{error}"
    );
}

/// Verify that unsupported TLS types receive REFUSED/EDE21 (RFC 9103, Section 7.8).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tls_query_returns_not_supported_for_unserved_type() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "type-refusal-key", KeyRole::Admin).await;

    for key in [None, Some(&key)] {
        for class in [Class::IN, Class::CH] {
            let mut builder = MessageBuilder::new_vec();
            builder.header_mut().set_id(93);
            let mut question = builder.question();
            question
                .push((
                    &dns::parse_name(&format!("www.{zone_name}")).unwrap(),
                    Rtype::A,
                    class,
                ))
                .unwrap();
            let mut query = question.additional();
            query
                .opt(|opt| {
                    opt.set_udp_payload_size(1232);
                    Ok(())
                })
                .unwrap();
            let response = dns::exchange_request(query, key, |message| {
                dns::exchange_tls(app.dns_tls_port(), message, common::dot_client(&app))
            })
            .unwrap();

            assert_eq!(response.header().rcode(), Rcode::REFUSED, "{class}");
            assert_eq!(
                extended_error_code(response.as_slice()),
                ExtendedErrorCode::NOT_SUPPORTED
            );
            assert_eq!(tsig::parse_tsig_presence(&response).unwrap(), key.is_some());
        }
    }
}

/// Verify that unsupported NOTIFY is refused before class checks on every transport.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tls_notify_returns_refused_with_not_supported() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "notify-refusal-key", KeyRole::Admin).await;

    for key in [None, Some(&key)] {
        for class in [Class::IN, Class::CH] {
            let mut builder = MessageBuilder::new_vec();
            builder.header_mut().set_id(9103);
            builder.header_mut().set_opcode(Opcode::NOTIFY);
            builder.header_mut().set_aa(true);
            let mut question = builder.question();
            question
                .push((&dns::parse_name(zone_name).unwrap(), Rtype::SOA, class))
                .unwrap();
            let mut request = question.additional();
            request
                .opt(|opt| {
                    opt.set_udp_payload_size(1232);
                    Ok(())
                })
                .unwrap();
            let response = dns::exchange_request(request, key, |message| {
                for response in [
                    dns::exchange_udp(app.dns_port(), message)?,
                    dns::exchange_tcp(app.dns_port(), message)?,
                ] {
                    let response = Message::from_octets(response).unwrap();

                    assert_eq!(response.header().rcode(), Rcode::NOTIMP);
                    assert_eq!(
                        extended_error_code(response.as_slice()),
                        ExtendedErrorCode::NOT_SUPPORTED
                    );

                    if let Some(key) = key {
                        tsig::verify_response_mac(message, &response, key).unwrap();
                    }
                }

                dns::exchange_tls(app.dns_tls_port(), message, common::dot_client(&app))
            })
            .unwrap();

            assert_eq!(response.header().rcode(), Rcode::REFUSED);
            assert_eq!(
                extended_error_code(response.as_slice()),
                ExtendedErrorCode::NOT_SUPPORTED
            );
            assert_eq!(tsig::parse_tsig_presence(&response).unwrap(), key.is_some());
        }
    }
}

/// Verify that TLS class refusals retain NOTAUTH/EDE20 and TSIG signatures.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tls_supported_queries_reject_foreign_classes() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "class-refusal-key", KeyRole::Admin).await;

    for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR] {
        for key in [None, Some(&key)] {
            let mut builder = MessageBuilder::new_vec();
            builder.header_mut().set_id(5936);
            let mut question = builder.question();
            question
                .push((&dns::parse_name(zone_name).unwrap(), qtype, Class::CH))
                .unwrap();
            let mut query = question.additional();
            query
                .opt(|opt| {
                    opt.set_udp_payload_size(1232);
                    Ok(())
                })
                .unwrap();
            let response = dns::exchange_request(query, key, |message| {
                dns::exchange_tls(app.dns_tls_port(), message, common::dot_client(&app))
            })
            .unwrap();

            assert_eq!(response.header().rcode(), Rcode::NOTAUTH, "{qtype}");
            assert_eq!(
                extended_error_code(response.as_slice()),
                ExtendedErrorCode::NOT_AUTHORITATIVE
            );
            assert_eq!(response.sole_question().unwrap().qclass(), Class::CH);
            assert_eq!(tsig::parse_tsig_presence(&response).unwrap(), key.is_some());
        }
    }
}

/// Verify that TLS UPDATE is refused and authenticated replies are signed (RFC 9103,
/// Section 7.8; RFC 8945, Section 5.3).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tls_update_returns_not_supported() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "xot-update-key", KeyRole::Admin).await;

    for (query_id, key) in [(94, None), (95, Some(&key))] {
        let mut request = nsupdate::build_update(
            query_id,
            zone_name,
            Class::IN,
            &[],
            &[UpdateRecord::AddA {
                name: format!("host.{zone_name}."),
                ttl: 300,
                addr: "192.0.2.1".to_string(),
            }],
        )
        .unwrap();
        request
            .opt(|opt| {
                opt.set_udp_payload_size(1232);
                Ok(())
            })
            .unwrap();

        if let Some(key) = key {
            tsig::sign(&mut request, key).unwrap();
        }

        let response = dns::exchange_tls(
            app.dns_tls_port(),
            &request.finish(),
            common::dot_client(&app),
        )
        .unwrap();

        assert_eq!(
            Message::from_octets(response.as_slice())
                .unwrap()
                .header()
                .rcode(),
            Rcode::REFUSED
        );
        assert_eq!(
            extended_error_code(&response),
            ExtendedErrorCode::NOT_SUPPORTED
        );
        let response = Message::from_octets(response).unwrap();

        assert_eq!(tsig::parse_tsig_presence(&response).unwrap(), key.is_some());
    }
}

/// Verify that TLS UPDATE is refused from its header, before a body that no
/// UPDATE parse accepts is read (RFC 9103, Section 7.8).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tls_update_returns_not_supported_when_body_is_malformed() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // A zone section naming type A, which RFC 2136, Section 2.3 rules out.
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(96);
    builder.header_mut().set_opcode(Opcode::UPDATE);
    let mut zone_section = builder.question();
    zone_section
        .push((&dns::parse_name(zone_name).unwrap(), Rtype::A, Class::IN))
        .unwrap();
    let mut request = zone_section.additional();
    request
        .opt(|opt| {
            opt.set_udp_payload_size(1232);
            Ok(())
        })
        .unwrap();

    let response = dns::exchange_tls(
        app.dns_tls_port(),
        &request.finish(),
        common::dot_client(&app),
    )
    .unwrap();

    assert_eq!(
        Message::from_octets(response.as_slice())
            .unwrap()
            .header()
            .rcode(),
        Rcode::REFUSED
    );
    assert_eq!(
        extended_error_code(&response),
        ExtendedErrorCode::NOT_SUPPORTED
    );
}

/// Read the extended error code a refusal names in its OPT.
fn extended_error_code(response: &[u8]) -> ExtendedErrorCode {
    Message::from_octets(response)
        .unwrap()
        .opt()
        .expect("the refusal carries an OPT")
        .opt()
        .iter::<ExtendedError<_>>()
        .next()
        .expect("the refusal names its reason")
        .unwrap()
        .code()
}
