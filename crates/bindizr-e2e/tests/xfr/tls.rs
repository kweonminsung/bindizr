//! Zone transfers over TLS (XoT, RFC 9103): the second listener serves what
//! the plain one does, but admits a request only when its TSIG key and its
//! address both pass, as Section 7.5 requires without mTLS.

use domain::{
    base::{
        Message, MessageBuilder,
        iana::{Class, ExtendedErrorCode, OptRcode, Rcode, Rtype, TsigRcode},
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

/// Verify that over TLS a transfer needs its key and a registered address
/// together, while the plain listener keeps admitting either alone.
#[tokio::test]
#[serial]
async fn a_transfer_over_tls_needs_the_key_and_a_registered_address() {
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
            for serial in [current, current + 1] {
                let query = build_ixfr_query(zone_name, serial);
                let response = exchange_request(query, Some(&key), |message| {
                    exchange_xot(app.dns_tls_port(), message, dot_client(&app))
                })
                .unwrap();
                if registered {
                    assert_eq!(response.header().rcode(), Rcode::NOERROR);
                    assert!(response.header().aa() && !response.header().tc());
                    assert_eq!(response.sole_question().unwrap().qtype(), Rtype::IXFR);
                    if serial == current {
                        assert_eq!(response.header_counts().ancount(), 1);
                    } else {
                        assert!(response.header_counts().ancount() > 1);
                    }
                    let soa = response
                        .answer()
                        .unwrap()
                        .limit_to::<Soa<_>>()
                        .next()
                        .unwrap()
                        .unwrap();
                    assert_eq!(soa.data().serial().into_int(), current);
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
async fn edns_dnssec_ok_is_echoed_over_tls() {
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

/// Verify that `dns.transfer.require_tls` refuses a transfer over plain TCP
/// and UDP while SOA queries and the transfer over TLS keep working
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
async fn a_reload_picks_up_a_renewed_certificate() {
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
async fn the_handshake_refuses_tls_1_2_and_a_foreign_alpn() {
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
async fn a_query_the_tls_listener_does_not_serve_is_refused_as_not_supported() {
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

/// Verify that an UPDATE sent to the TLS listener, which serves transfers
/// alone, is refused as not supported (RFC 9103, Section 7.8), under its key
/// when it has one (RFC 8945, Section 5.3).
#[tokio::test]
#[serial]
async fn an_update_over_tls_is_refused_as_not_supported() {
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
