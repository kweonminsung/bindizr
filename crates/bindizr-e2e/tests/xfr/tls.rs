//! Zone transfers over TLS require both TSIG and address authorization
//! without mTLS (RFC 9103, Section 7.5).

use domain::{
    base::{
        Message, MessageBuilder,
        iana::{Class, ExtendedErrorCode, Opcode, OptRcode, Rcode, Rtype, TsigRcode},
        opt::exterr::ExtendedError,
    },
    rdata::{
        Soa,
        tsig::{Time48, Tsig},
    },
    tsig::ClientTransaction,
};
use reqwest::{Method, StatusCode};
use rustls::{
    ClientConfig, RootCertStore, SupportedProtocolVersion, pki_types::CertificateDer, version,
};
use serial_test::serial;

use super::common::{build_edns_query, build_ixfr_query, build_multi_question_query, counter};
use crate::common::{
    TestApp, TestAppOptions, assert_cli_failure_contains, axfr,
    dns::{
        exchange_request, exchange_udp,
        nsupdate::{UpdateRecord, build_update},
        parse_name, probe_zone_soa,
        tsig::{KeyRole, create_tsig_key, is_signed, sign, verify_response_mac},
    },
    exchange_xot, xot,
};

/// A bindizr serving XoT beside plain TCP.
async fn xot_app() -> TestApp {
    TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await
}

/// A client trusting the run's certificate, speaking `versions` and offering
/// `alpn`.
fn xot_client(
    cert: &CertificateDer<'static>,
    versions: &[&'static SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).expect("trust the test certificate");
    let mut client = ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = alpn.iter().map(|token| token.to_vec()).collect();
    client
}

/// The client a BIND, Knot, or NSD secondary is: TLS 1.3 offering "dot".
fn dot_client(app: &TestApp) -> ClientConfig {
    xot_client(app.tls_cert(), &[&version::TLS13], &[b"dot"])
}

/// Finish a signed transfer, verifying every frame and its closing signature.
fn exchange_signed_boundary_transfer<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    mut request: domain::base::message_builder::AdditionalBuilder<Vec<u8>>,
    key: domain::tsig::Key,
) -> Vec<Message<Vec<u8>>> {
    use crate::common::dns::{read_frame, write_frame};

    let mut client =
        domain::tsig::ClientSequence::request(key, &mut request, Time48::now()).unwrap();
    write_frame(stream, &request.finish()).unwrap();
    let mut messages = Vec::new();
    let mut soa_count = 0;
    while soa_count < 2 {
        let mut message =
            Message::from_octets(read_frame(stream).unwrap().expect("closing SOA")).unwrap();
        assert_eq!(message.header().rcode(), Rcode::NOERROR);
        client.answer(&mut message, Time48::now()).unwrap();
        soa_count += message
            .answer()
            .unwrap()
            .map(Result::unwrap)
            .filter(|record| record.rtype() == Rtype::SOA)
            .count();
        messages.push(message);
    }
    client.done().unwrap();
    messages
}

/// Maximum storable RDATA fits SHA-512-signed EDNS AXFR over TCP and TLS.
#[tokio::test]
#[serial]
async fn maximum_record_value_transfers_with_signed_edns_and_long_names() {
    use std::str::FromStr;

    use base64::Engine;
    use domain::tsig::{Algorithm, Key, KeyName};
    use serde_json::json;

    use crate::common::dns::{connect_tcp, connect_tls};

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
    let key_name = longest_name(['k', 'l', 'm', 'n']);
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
                "name": key_name, "algorithm": "hmac-sha512", "role_name": "admin"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let secret = base64::engine::general_purpose::STANDARD
        .decode(body["secret"].as_str().unwrap())
        .unwrap();
    let key = Key::new(
        Algorithm::Sha512,
        &secret,
        KeyName::from_str(&key_name).unwrap(),
        None,
        None,
    )
    .unwrap();
    // 64,618 wire bytes leave room for maximal names, TSIG, OPT and keepalive.
    let value = format!("3 0 0 {}", "AB".repeat(64_618 - 3));
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
    let serial = app.read_zone_serial(&zone_name).await;
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
    assert_eq!(app.read_zone_serial(&zone_name).await, serial);

    let plain = exchange_signed_boundary_transfer(
        &mut connect_tcp(app.dns_port()).unwrap(),
        build_edns_query(&zone_name, Rtype::AXFR, &[(0, false)]),
        key.clone(),
    );
    let tls = exchange_signed_boundary_transfer(
        &mut connect_tls(app.dns_tls_port(), dot_client(&app)).unwrap(),
        build_edns_query(&zone_name, Rtype::AXFR, &[(0, false)]),
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
                    assert_eq!(record.rdlen(), 64_618);
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

/// SOA replies carry verifiable RRSIGs only with DO; IXFR stays SOA-only.
#[tokio::test]
#[serial]
async fn soa_queries_return_current_signatures_when_dnssec_is_requested() {
    use domain::{
        base::{ToName, rdata::ComposeRecordData},
        rdata::{Dnskey, Rrsig},
    };
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use serde_json::json;

    use crate::common::exchange_tcp;

    let app = xot_app().await;
    app.create_secondary("loopback", "127.0.0.1:9").await;
    let zone = app.create_test_zone().await;
    let name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "soa-signature-key", KeyRole::Admin).await;
    for stage in 0..3 {
        if stage == 1 {
            let (status, _) = app
                .send_request(
                    Method::POST,
                    &format!("/zones/{name}/dnssec"),
                    Some(json!({"parent_ns_addrs": ["127.0.0.1:9"]})),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED);
        } else if stage == 2 {
            let (status, _) = app.send_request(Method::POST, "/records", Some(json!({"zone_name": name, "name": "new", "type": "A", "value": "192.0.2.1", "ttl": 3600}))).await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let current_serial = app.read_zone_serial(name).await as u32;
        let transfer = exchange_request(
            build_edns_query(name, Rtype::AXFR, &[]),
            Some(&key),
            |request| exchange_tcp(app.dns_port(), request),
        )
        .unwrap();
        let public = transfer
            .answer()
            .unwrap()
            .limit_to::<Dnskey<_>>()
            .next()
            .map(|record| record.unwrap().data().public_key().to_vec());
        for do_bit in [false, true] {
            for signed in [false, true] {
                for transport in ["udp", "tcp", "tls"] {
                    let signer = if signed || transport == "tls" {
                        Some(&key)
                    } else {
                        None
                    };
                    let response = exchange_request(
                        build_edns_query(name, Rtype::SOA, &[(0, do_bit)]),
                        signer,
                        |request| match transport {
                            "udp" => exchange_udp(app.dns_port(), request),
                            "tcp" => exchange_tcp(app.dns_port(), request),
                            _ => exchange_xot(app.dns_tls_port(), request, dot_client(&app)),
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
                    assert_eq!(signatures.len(), usize::from(stage > 0 && do_bit));
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
        let response = exchange_request(
            build_edns_query(name, Rtype::IXFR, &[(0, true)]),
            Some(&key),
            |request| exchange_udp(app.dns_port(), request),
        )
        .unwrap();
        assert_eq!(response.header_counts().ancount(), 1);
        if stage == 2 {
            let long_name = format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61)
            );
            let long_key = create_tsig_key(&app, &long_name, KeyRole::Admin).await;
            for tcp in [false, true] {
                let mut query = MessageBuilder::new_vec().question();
                query
                    .push((&parse_name(name).unwrap(), Rtype::SOA))
                    .unwrap();
                let mut query = query.additional();
                query
                    .opt(|opt| {
                        opt.set_udp_payload_size(512);
                        opt.set_dnssec_ok(true);
                        Ok(())
                    })
                    .unwrap();
                let response = exchange_request(query, Some(&long_key), |request| {
                    if tcp {
                        exchange_tcp(app.dns_port(), request)
                    } else {
                        exchange_udp(app.dns_port(), request)
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

/// Verify that over TLS a transfer needs its key and a registered address
/// together, while the plain listener keeps admitting either alone.
#[tokio::test]
#[serial]
async fn tls_transfer_requires_key_and_registered_address() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "xot-key", KeyRole::Admin).await;

    // RFC 9103, Section 7.5: the key alone is refused here, though the plain
    // listener takes it.
    let outcome = xot(app.dns_tls_port(), zone_name, Some(&key), dot_client(&app)).expect("XoT");
    assert_eq!(outcome.refusal(), Rcode::REFUSED);
    let outcome = axfr(app.dns_port(), zone_name, Some(&key)).expect("AXFR");
    assert!(outcome.records() >= 3);

    // The address alone is refused over TLS as well.
    app.create_secondary("loopback", "127.0.0.1").await;
    let outcome = xot(app.dns_tls_port(), zone_name, None, dot_client(&app)).expect("XoT");
    assert_eq!(outcome.refusal(), Rcode::REFUSED);

    // Both together: served, every envelope verified under the key.
    let outcome = xot(app.dns_tls_port(), zone_name, Some(&key), dot_client(&app)).expect("XoT");
    assert!(outcome.records() >= 3);

    // The transfer log and the metric say which transport served each one.
    let (status, body) = app
        .send_request(Method::GET, "/secondaries/loopback/transfers", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["transfers"][0]["transport"], "tls", "{body}");
    let tls_ok = counter(
        &app,
        "bindizr_xfr_total",
        &[r#"type="axfr""#, r#"result="ok""#, r#"transport="tls""#],
    )
    .await;
    let tcp_ok = counter(
        &app,
        "bindizr_xfr_total",
        &[r#"type="axfr""#, r#"result="ok""#, r#"transport="tcp""#],
    )
    .await;
    assert_eq!(tls_ok, 1.0);
    assert_eq!(tcp_ok, 1.0);
}

/// Apply IXFR serial policy over TLS after both transfer gates pass.
#[tokio::test]
#[serial]
async fn ixfr_serial_policy_over_tls_requires_a_key_and_registered_address() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let key = create_tsig_key(&app, "xot-ixfr-key", KeyRole::Admin).await;
    let current = u32::try_from(zone["serial"].as_u64().unwrap()).unwrap();
    for registered in [false, true] {
        if registered {
            app.create_secondary("loopback", "127.0.0.1").await;
        }
        for zone_name in [zone["name"].as_str().unwrap(), "catalog.bindizr"] {
            let expected = if registered {
                let query = build_edns_query(zone_name, Rtype::SOA, &[]);
                let response = exchange_request(query, Some(&key), |message| {
                    exchange_xot(app.dns_tls_port(), message, dot_client(&app))
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
                let query = build_ixfr_query(zone_name, serial);
                let response = exchange_request(query, Some(&key), |message| {
                    exchange_xot(app.dns_tls_port(), message, dot_client(&app))
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

/// Echo DO in signed TLS responses, including REFUSED and BADVERS.
#[tokio::test]
#[serial]
async fn tls_response_preserves_edns_dnssec_ok() {
    let app = xot_app().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "xot-dnssec-ok-key", KeyRole::Admin).await;
    for dnssec_ok in [false, true] {
        for version in [0, 1] {
            for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR, Rtype::A] {
                let query = build_edns_query(zone_name, qtype, &[(version, dnssec_ok)]);
                let response = exchange_request(query, Some(&key), |message| {
                    exchange_xot(app.dns_tls_port(), message, dot_client(&app))
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

/// Return authenticated BADTIME with OPT over TLS.
#[tokio::test]
#[serial]
async fn badtime_tls_responses_preserve_edns_and_verify() {
    let app = xot_app().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "badtime-tls-key", KeyRole::Admin).await;
    let signed_at = Time48::from_u64(u64::from(Time48::now()) - 3600);
    for dnssec_ok in [false, true] {
        for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR] {
            let mut query = build_edns_query(zone_name, qtype, &[(0, dnssec_ok)]);
            ClientTransaction::request_with_fudge(
                key.to_tsig_key().unwrap(),
                &mut query,
                signed_at,
                17,
            )
            .unwrap();
            let query = query.finish();
            let response = exchange_xot(app.dns_tls_port(), &query, dot_client(&app)).unwrap();
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
            verify_response_mac(&query, &response, &key).unwrap();
        }
    }
}

/// Authenticate truncated TLS queries before applying time and length policy.
#[tokio::test]
#[serial]
async fn truncated_tls_queries_follow_tsig_validation_order() {
    let app = xot_app().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "truncated-tls-key", KeyRole::Admin).await;
    for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR] {
        for (age, corrupt, expected) in [
            (0, false, TsigRcode::BADTRUNC),
            (3600, false, TsigRcode::BADTIME),
            (0, true, TsigRcode::BADSIG),
            (3600, true, TsigRcode::BADSIG),
        ] {
            let signed_at = Time48::from_u64(u64::from(Time48::now()) - age);
            let mut query = build_edns_query(zone_name, qtype, &[(0, true)]);
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
            let response = Message::from_octets(
                exchange_xot(app.dns_tls_port(), &query, dot_client(&app)).unwrap(),
            )
            .unwrap();
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
                verify_response_mac(&query, &response, &key).unwrap();
            }
            assert_eq!(
                tsig.data().other().len(),
                if expected == TsigRcode::BADTIME { 6 } else { 0 }
            );
        }
    }
}

/// Sign FORMERR responses to multi-question queries over TLS.
#[tokio::test]
#[serial]
async fn multi_question_queries_receive_signed_formerr_over_tls() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "xot-multi-question-key", KeyRole::Admin).await;
    for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR] {
        let query = build_multi_question_query(zone_name, qtype, Class::IN, Some(0));
        let response = exchange_request(query, Some(&key), |message| {
            exchange_xot(app.dns_tls_port(), message, dot_client(&app))
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
        build_multi_question_query(zone_name, Rtype::SOA, Class::IN, None).finish();
    unreadable.truncate(12);
    let response = exchange_xot(app.dns_tls_port(), &unreadable, dot_client(&app)).unwrap();
    let response = Message::from_octets(response).unwrap();
    assert_eq!(response.header().rcode(), Rcode::FORMERR);
    assert_eq!(response.header().id(), 9619);
    assert_eq!(response.header_counts().qdcount(), 0);
    assert_eq!(response.header_counts().ancount(), 0);
}

/// Verify `require_tls` refuses plain TCP/UDP transfers while allowing SOA and TLS
/// (RFC 9103, Section 11).
#[tokio::test]
#[serial]
async fn require_tls_refuses_a_transfer_over_plain_tcp() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        dns_transfer_require_tls: true,
        ..Default::default()
    })
    .await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "xot-only-key", KeyRole::Admin).await;
    app.create_secondary("loopback", "127.0.0.1").await;

    // RFC 8945, Section 5.3: the refusal of a signed request is signed.
    let outcome = axfr(app.dns_port(), zone_name, Some(&key)).expect("AXFR");
    assert_eq!(outcome.refusal(), Rcode::REFUSED);
    assert!(outcome.refusal_signed());
    // A UDP IXFR is a transfer request too; a SOA query keeps answering.
    let frame = exchange_udp(
        app.dns_port(),
        &build_edns_query(zone_name, Rtype::IXFR, &[(0, false)]).finish(),
    )
    .unwrap();
    let response = Message::from_octets(frame.as_slice()).unwrap();
    assert_eq!(response.header().rcode(), Rcode::REFUSED);
    assert!(probe_zone_soa(app.dns_port(), zone_name));

    // The refusal is logged against the secondary with its reason; the log
    // keeps one row per zone, so it is read before the transfer that works.
    let (status, body) = app
        .send_request(Method::GET, "/secondaries/loopback/transfers", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refused = &body["transfers"][0];
    assert_eq!(refused["result"], "refused", "{body}");
    assert_eq!(refused["transport"], "tcp", "{body}");
    assert!(
        refused["error"].as_str().unwrap().contains("require TLS"),
        "{body}"
    );

    let outcome = xot(app.dns_tls_port(), zone_name, Some(&key), dot_client(&app)).expect("XoT");
    assert!(outcome.records() >= 3);
}

/// Verify that `config reload` re-reads the certificate pair, so a renewed
/// certificate serves without a restart.
#[tokio::test]
#[serial]
async fn config_reload_replaces_dns_tls_certificate() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "renewal-key", KeyRole::Admin).await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let outcome = xot(app.dns_tls_port(), zone_name, Some(&key), dot_client(&app)).expect("XoT");
    assert!(outcome.records() >= 3);

    let renewed = app.renew_test_certificate();
    let output = app.run_cli_success(&["config", "reload"], None).await;
    assert!(output.contains("dns.tls certificate"), "{output}");

    let client = xot_client(&renewed, &[&version::TLS13], &[b"dot"]);
    let outcome = xot(app.dns_tls_port(), zone_name, Some(&key), client).expect("XoT");
    assert!(outcome.records() >= 3);
    // The certificate the run started with is no longer presented: the new
    // one carries the same name, so the stale root fails on the signature.
    let error = xot(app.dns_tls_port(), zone_name, Some(&key), dot_client(&app)).unwrap_err();
    assert!(error.contains("invalid peer certificate"), "{error}");

    // A pair that does not load refuses the whole reload and leaves the
    // renewed certificate serving.
    app.corrupt_test_certificate();
    let output = app.run_cli(&["config", "reload"], None).await;
    assert_cli_failure_contains(&["config", "reload"], &output, "nothing was reloaded");
    let client = xot_client(&renewed, &[&version::TLS13], &[b"dot"]);
    let outcome = xot(app.dns_tls_port(), zone_name, Some(&key), client).expect("XoT");
    assert!(outcome.records() >= 3);
}

/// Verify that the handshake refuses TLS 1.2 and an ALPN without "dot", and
/// that a client naming no ALPN is closed without a transfer.
#[tokio::test]
#[serial]
async fn tls_handshake_rejects_tls_1_2_and_foreign_alpn() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (port, cert) = (app.dns_tls_port(), app.tls_cert());

    // RFC 9103, Section 7.2: TLS 1.3 or later only.
    let client = xot_client(cert, &[&version::TLS12], &[b"dot"]);
    let error = xot(port, zone_name, None, client).unwrap_err();
    assert!(error.contains("ProtocolVersion"), "{error}");

    // RFC 9103, Section 7.1: the handshake selects "dot"; a client offering
    // only another token is left without a protocol.
    let client = xot_client(cert, &[&version::TLS13], &[b"h2"]);
    let error = xot(port, zone_name, None, client).unwrap_err();
    assert!(error.contains("NoApplicationProtocol"), "{error}");

    // A client naming no ALPN completes the handshake, so the server closes
    // the session instead of answering.
    let client = xot_client(cert, &[&version::TLS13], &[]);
    let error = xot(port, zone_name, None, client).unwrap_err();
    assert!(
        error.contains("without its closing SOA") || error.contains("close_notify"),
        "{error}"
    );
}

/// Verify that a query the TLS listener does not serve is REFUSED with
/// extended DNS error 21, Not Supported (RFC 9103, Section 7.8).
#[tokio::test]
#[serial]
async fn tls_query_returns_not_supported_for_unserved_type() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(93);
    let mut question = builder.question();
    question
        .push((&parse_name(&format!("www.{zone_name}")).unwrap(), Rtype::A))
        .unwrap();
    let mut additional = question.additional();
    additional
        .opt(|opt| {
            opt.set_udp_payload_size(1232);
            Ok(())
        })
        .unwrap();

    let frame =
        exchange_xot(app.dns_tls_port(), &additional.finish(), dot_client(&app)).expect("XoT");

    let response = Message::from_octets(frame.as_slice()).unwrap();
    assert_eq!(response.header().rcode(), Rcode::REFUSED);
    assert_eq!(
        extended_error_code(&frame),
        ExtendedErrorCode::NOT_SUPPORTED
    );
}

/// Unsupported NOTIFY is REFUSED on TLS and NOTIMP on plain transports.
#[tokio::test]
#[serial]
async fn tls_notify_returns_refused_with_not_supported() {
    use crate::common::exchange_tcp;

    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "notify-refusal-key", KeyRole::Admin).await;
    for key in [None, Some(&key)] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(9103);
        builder.header_mut().set_opcode(Opcode::NOTIFY);
        builder.header_mut().set_aa(true);
        let mut question = builder.question();
        question
            .push((&parse_name(zone_name).unwrap(), Rtype::SOA))
            .unwrap();
        let mut request = question.additional();
        request
            .opt(|opt| {
                opt.set_udp_payload_size(1232);
                Ok(())
            })
            .unwrap();
        let response = exchange_request(request, key, |request| {
            for bytes in [
                exchange_udp(app.dns_port(), request)?,
                exchange_tcp(app.dns_port(), request)?,
            ] {
                let message = Message::from_octets(bytes).unwrap();
                assert_eq!(message.header().rcode(), Rcode::NOTIMP);
                assert_eq!(
                    extended_error_code(message.as_slice()),
                    ExtendedErrorCode::NOT_SUPPORTED
                );
                if let Some(key) = key {
                    verify_response_mac(request, &message, key).unwrap();
                }
            }
            exchange_xot(app.dns_tls_port(), request, dot_client(&app))
        })
        .unwrap();
        assert_eq!(response.header().rcode(), Rcode::REFUSED);
        assert_eq!(
            extended_error_code(response.as_slice()),
            ExtendedErrorCode::NOT_SUPPORTED
        );
        assert_eq!(is_signed(&response).unwrap(), key.is_some());
    }
}

/// Verify the transfer-only TLS listener refuses UPDATE (RFC 9103, Section 7.8),
/// signing the refusal when a key is present (RFC 8945, Section 5.3).
#[tokio::test]
#[serial]
async fn tls_update_returns_not_supported() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "xot-update-key", KeyRole::Admin).await;

    for (query_id, key) in [(94, None), (95, Some(&key))] {
        let mut update = build_update(
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
        update
            .opt(|opt| {
                opt.set_udp_payload_size(1232);
                Ok(())
            })
            .unwrap();
        if let Some(key) = key {
            sign(&mut update, key).unwrap();
        }

        let frame =
            exchange_xot(app.dns_tls_port(), &update.finish(), dot_client(&app)).expect("XoT");

        let response = Message::from_octets(frame.as_slice()).unwrap();
        assert_eq!(response.header().rcode(), Rcode::REFUSED);
        assert_eq!(
            extended_error_code(&frame),
            ExtendedErrorCode::NOT_SUPPORTED
        );
        let response = Message::from_octets(frame).unwrap();
        assert_eq!(is_signed(&response).unwrap(), key.is_some());
    }
}

/// The extended error code a refusal names in its OPT.
fn extended_error_code(frame: &[u8]) -> ExtendedErrorCode {
    Message::from_octets(frame)
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
