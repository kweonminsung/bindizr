//! Zone transfers over TLS (XoT, RFC 9103): the second listener serves what
//! the plain one does, but admits a request only when its TSIG key and its
//! address both pass, as Section 7.5 requires without mTLS.

use domain::base::{
    Message, MessageBuilder,
    iana::{ExtendedErrorCode, Rcode, Rtype},
    opt::exterr::ExtendedError,
};
use reqwest::{Method, StatusCode};
use rustls::{
    ClientConfig, RootCertStore, SupportedProtocolVersion, pki_types::CertificateDer, version,
};
use serial_test::serial;

use crate::common::{
    TestApp, TestAppOptions, axfr,
    dns::{
        nsupdate::{KeyRole, UpdateRecord, build_update, create_tsig_key, is_signed, sign},
        parse_name,
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
    let tls_ok = super::counter(
        &app,
        "bindizr_xfr_total",
        &[r#"type="axfr""#, r#"result="ok""#, r#"transport="tls""#],
    )
    .await;
    let tcp_ok = super::counter(
        &app,
        "bindizr_xfr_total",
        &[r#"type="axfr""#, r#"result="ok""#, r#"transport="tcp""#],
    )
    .await;
    assert_eq!(tls_ok, 1.0);
    assert_eq!(tcp_ok, 1.0);
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
