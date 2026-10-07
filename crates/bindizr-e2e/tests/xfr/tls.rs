//! Zone transfers over TLS (XoT, RFC 9103): the second listener serves what
//! the plain one does, under the same key or address check.

use domain::base::iana::Rcode;
use reqwest::{Method, StatusCode};
use rustls::{
    ClientConfig, RootCertStore, SupportedProtocolVersion, pki_types::CertificateDer, version,
};
use serial_test::serial;

use crate::common::{
    TestApp, TestAppOptions, axfr,
    dns::nsupdate::{KeyRole, create_tsig_key},
    xot,
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

/// Verify that the TLS listener admits an unsigned transfer by the same
/// secondary registry as the plain one, which keeps serving beside it.
#[tokio::test]
#[serial]
async fn an_unsigned_transfer_over_tls_follows_the_secondary_registry() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let outcome = xot(app.dns_tls_port(), zone_name, None, dot_client(&app)).expect("XoT");
    assert_eq!(outcome.refusal(), Rcode::REFUSED);

    app.create_secondary("loopback", "127.0.0.1").await;
    let outcome = xot(app.dns_tls_port(), zone_name, None, dot_client(&app)).expect("XoT");
    assert!(outcome.records() >= 3);

    // SOA polls and older secondaries still arrive on the plain port.
    let outcome = axfr(app.dns_port(), zone_name, None).expect("AXFR");
    assert!(outcome.records() >= 3);

    // The transfer log and the metric say which transport served each one.
    let (status, body) = app
        .send_request(Method::GET, "/secondaries/loopback/transfers", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["transfers"][0]["transport"], "tcp", "{body}");
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

/// Verify that a signed transfer over TLS is answered under its key, every
/// envelope verified.
#[tokio::test]
#[serial]
async fn a_signed_transfer_over_tls_answers_under_its_key() {
    let app = xot_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "xot-key", KeyRole::Admin).await;

    let outcome = xot(app.dns_tls_port(), zone_name, Some(&key), dot_client(&app)).expect("XoT");

    assert!(outcome.records() >= 3);
}

/// Verify that the handshake refuses TLS 1.2 and an ALPN without "dot", and
/// serves a client naming no ALPN.
#[tokio::test]
#[serial]
async fn the_handshake_refuses_tls_1_2_and_a_foreign_alpn() {
    let app = xot_app().await;
    app.create_secondary("loopback", "127.0.0.1").await;
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

    // ALPN is negotiated only when both sides name it.
    let client = xot_client(cert, &[&version::TLS13], &[]);
    let outcome = xot(port, zone_name, None, client).expect("XoT");
    assert!(outcome.records() >= 3);
}
