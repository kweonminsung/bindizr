//! Zone transfers as a secondary runs them: unsigned under the address ACL,
//! and signed under a TSIG key the way `primaries { addr key k; }` does.

mod catalog;
mod common;
mod tls;

use std::collections::HashMap;
use std::io;
use std::net::{TcpStream, UdpSocket};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use domain::base::iana::{Class, ExtendedErrorCode, Opcode, OptRcode, Rcode, Rtype, TsigRcode};
use domain::base::message_builder::AdditionalBuilder;
use domain::base::opt::exterr::ExtendedError;
use domain::base::{Message, MessageBuilder, Serial, Ttl};
use domain::rdata::tsig::{Time48, Tsig};
use domain::rdata::{A, Soa};
use domain::tsig::{Algorithm, ClientSequence, ClientTransaction};
use reqwest::{Method, StatusCode};
use serde_json::json;
use tokio::time;

use crate::common::dns::nsupdate::UpdateRecord;
use crate::common::dns::tsig::{KeyRole, SigningKey};
use crate::common::dns::{TransferResult, nsupdate, tsig};
use crate::common::{TestApp, TestAppOptions, dns};

/// Start a bindizr whose transfer ACL admits the test's own loopback pull.
async fn transfer_app() -> TestApp {
    let app = TestApp::start_local().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    app
}

/// Verify that UDP errors fit without losing their signed error and that streams retain the
/// question.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn oversized_tsig_errors_preserve_error_and_authentication_across_transports() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;

    for algorithm in [
        Algorithm::Sha1,
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
    ] {
        let tsig_key_name = format!(
            "{}.{}.{}.{}",
            "k".repeat(63),
            "l".repeat(63),
            "m".repeat(63),
            "n".repeat(
                1 + 64 - algorithm.native_len() + usize::from(algorithm == Algorithm::Sha1) * 2
            )
        );

        let (status, body) = app
            .send_request(
                Method::POST,
                "/tsig-keys",
                Some(
                    json!({ "name": tsig_key_name, "role_name": "admin", "algorithm": algorithm.to_string() }),
                ),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
        let key = SigningKey {
            name: tsig_key_name,
            secret: body["secret"].as_str().unwrap().to_string(),
            algorithm,
        };

        for truncated in [false, true] {
            for stale in [false, true] {
                if !truncated && !stale {
                    continue;
                }

                for edns in [None, Some(512), Some(1232)] {
                    for (opcode, qtype) in [
                        (Opcode::QUERY, Rtype::SOA),
                        (Opcode::QUERY, Rtype::AXFR),
                        (Opcode::UPDATE, Rtype::SOA),
                    ] {
                        let zone_name = format!(
                            "{}.{}.{}.{}",
                            "a".repeat(63),
                            "b".repeat(63),
                            "c".repeat(if edns.is_some() {
                                52
                            } else {
                                63
                            }),
                            "d".repeat(if truncated {
                                1 + algorithm.native_len() / 2
                            } else {
                                1
                            })
                        );
                        let mut builder = MessageBuilder::new_vec();
                        builder.header_mut().set_id(8945);
                        builder.header_mut().set_opcode(opcode);
                        builder.header_mut().set_rd(true);
                        let mut question = builder.question();
                        question
                            .push((dns::parse_name(&zone_name).unwrap(), qtype))
                            .unwrap();
                        let mut query = question.additional();

                        if let Some(size) = edns {
                            query
                                .opt(|opt| {
                                    opt.set_udp_payload_size(size);
                                    opt.set_dnssec_ok(true);
                                    Ok(())
                                })
                                .unwrap();
                        }

                        let signed_at = Time48::from_u64(
                            u64::from(Time48::now())
                                - if stale {
                                    3600
                                } else {
                                    0
                                },
                        );
                        let mac_len = if truncated {
                            algorithm.native_len() / 2
                        } else {
                            algorithm.native_len()
                        };
                        ClientTransaction::request_with_fudge(
                            key.to_tsig_key_with_mac_len(mac_len).unwrap(),
                            &mut query,
                            signed_at,
                            17,
                        )
                        .unwrap();
                        let query = query.finish();

                        assert_eq!(query.len(), 509);

                        for transport in ["udp", "tcp", "tls"] {
                            let response = match transport {
                                "udp" => dns::exchange_udp(app.dns_port(), &query),
                                "tcp" => dns::exchange_tcp(app.dns_port(), &query),
                                _ => dns::exchange_tls(
                                    app.dns_tls_port(),
                                    &query,
                                    dns::dot_client(&app),
                                ),
                            }
                            .unwrap();
                            let response = Message::from_octets(response).unwrap();
                            let limit = usize::from(edns.unwrap_or(512));

                            if transport == "udp" {
                                assert!(response.as_slice().len() <= limit);
                            }

                            assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
                            assert_eq!(response.header().opcode(), opcode);
                            assert!(response.header().rd());
                            assert!(!response.header().tc());
                            assert_eq!(
                                response.header_counts().qdcount(),
                                u16::from(transport != "udp" || limit > 512)
                            );
                            let tsig = response
                                .additional()
                                .unwrap()
                                .limit_to::<Tsig<_, _>>()
                                .last()
                                .unwrap()
                                .unwrap();

                            assert_eq!(
                                tsig.data().error(),
                                if stale {
                                    TsigRcode::BADTIME
                                } else {
                                    TsigRcode::BADTRUNC
                                }
                            );
                            assert_eq!(tsig.data().mac().len(), algorithm.native_len());
                            assert_eq!(tsig.data().fudge(), 17);

                            if stale {
                                assert_eq!(tsig.data().time_signed(), signed_at);
                            }

                            assert_eq!(
                                tsig.data().other().len(),
                                if stale {
                                    6
                                } else {
                                    0
                                }
                            );
                            assert_eq!(
                                response.opt().map(|opt| opt.dnssec_ok()),
                                edns.map(|_| true)
                            );
                            tsig::verify_response_mac(&query, &response, &key).unwrap();
                        }
                    }
                }
            }
        }
    }
}

/// Verify that an upper-case TSIG algorithm name names the same key (RFC 1035, Section
/// 2.3.3); the digest takes the canonical form, so the MAC verifies.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_algorithm_names_match_regardless_of_case() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "upper-case-algorithm-key", KeyRole::Admin).await;

    let mut query = common::build_edns_query(zone_name, Rtype::SOA, &[]);
    tsig::sign(&mut query, &key).unwrap();
    let mut query = query.finish();
    let label = b"hmac-sha256";
    let index = query
        .windows(label.len())
        .rposition(|window| window == label)
        .unwrap();
    query[index..index + label.len()].make_ascii_uppercase();

    for response in [
        dns::exchange_udp(app.dns_port(), &query).unwrap(),
        dns::exchange_tcp(app.dns_port(), &query).unwrap(),
    ] {
        let response = Message::from_octets(response).unwrap();

        assert_eq!(response.header().rcode(), Rcode::NOERROR);
        assert!(tsig::parse_tsig_presence(&response).unwrap());
        tsig::verify_response_mac(&query, &response, &key).unwrap();
    }
}

/// Verify that SHA1 authenticates queries and updates (RFC 8945, Section 6).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn sha1_tsig_key_authenticates_queries_and_updates() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "sha1-key", "role_name": "admin", "algorithm": "hmac-sha1" })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["tsig_key"]["algorithm"], "hmac-sha1");
    let key = Arc::new(
        SigningKey {
            name: "sha1-key".to_string(),
            secret: body["secret"].as_str().unwrap().to_string(),
            algorithm: Algorithm::Sha1,
        }
        .to_tsig_key()
        .unwrap(),
    );

    for opcode in [Opcode::QUERY, Opcode::UPDATE] {
        let mut query = common::build_edns_query(zone_name, Rtype::SOA, &[]);
        query.header_mut().set_opcode(opcode);
        let client = ClientTransaction::request(key.clone(), &mut query, Time48::now()).unwrap();
        let response = dns::exchange_udp(app.dns_port(), &query.finish()).unwrap();
        let mut response = Message::from_octets(response).unwrap();

        assert_eq!(response.header().rcode(), Rcode::NOERROR);
        client.answer(&mut response, Time48::now()).unwrap();
    }
}

/// Verify that an unsigned transfer is admitted only while its secondary is
/// registered and enabled.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn unsigned_transfer_requires_registered_secondary() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Nobody is registered yet, so the address admits nothing.
    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, None).unwrap();

    assert_eq!(outcome.refusal(), Rcode::REFUSED);

    app.create_secondary("loopback", "127.0.0.1").await;

    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, None).unwrap();

    assert!(outcome.records() >= 3);

    // Disabling keeps the row but closes the ACL from the next request on.
    app.run_cli_success(
        &["secondary", "update", "loopback", "--enabled", "false"],
        None,
    )
    .await;

    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, None).unwrap();

    assert_eq!(outcome.refusal(), Rcode::REFUSED);

    app.run_cli_success(
        &["secondary", "update", "loopback", "--enabled", "true"],
        None,
    )
    .await;

    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, None).unwrap();

    assert!(outcome.records() >= 3);

    app.run_cli_success(&["secondary", "delete", "loopback"], None)
        .await;

    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, None).unwrap();

    assert_eq!(outcome.refusal(), Rcode::REFUSED);
}

/// Verify that a transfer question no zone can carry is answered NOTAUTH,
/// like a missing zone, rather than closing the connection.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn transfer_returns_notauth_for_invalid_zone_name() {
    let app = transfer_app().await;

    // RFC 5936, Section 2.2.1: a refusal is an RCODE, not a dropped
    // connection; the underscore label is one the zone type refuses.
    for zone_name in ["nozone.example.", "_foo.example."] {
        let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, None).unwrap();

        assert_eq!(outcome.refusal(), Rcode::NOTAUTH, "zone {zone_name}");
    }
}

/// Verify that an IXFR over UDP is answered with the zone's current SOA
/// alone and counts as a truncated transfer.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn udp_ixfr_returns_current_soa() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let ixfr_truncated = [
        r#"kind="ixfr""#,
        r#"result="truncated""#,
        r#"transport="udp""#,
    ];

    let truncated = app.read_counter("bindizr_xfr_total", &ixfr_truncated).await;
    let soa_ok = app
        .read_counter("bindizr_soa_queries_total", &[r#"result="ok""#])
        .await;

    // RFC 1995, Section 2: Windows DNS asks this way after a NOTIFY and goes
    // to TCP only when the answer's serial is ahead of its own.
    let response =
        dns::exchange_dns_query(app.dns_port(), zone_name, Rtype::IXFR.to_int()).unwrap();
    let header = response.header();

    assert_eq!(header.rcode(), Rcode::NOERROR);
    assert!(header.aa() && !header.tc());
    assert_eq!(response.sole_question().unwrap().qtype(), Rtype::IXFR);
    let answers: Vec<_> = response
        .answer()
        .unwrap()
        .limit_to::<Soa<_>>()
        .map(Result::unwrap)
        .collect();

    assert_eq!(answers.len(), 1);
    assert_eq!(
        u64::from(answers[0].data().serial().into_int()),
        zone["serial"].as_u64().unwrap()
    );

    // Counted as a transfer, as a UDP AXFR's TC answer is, not as an SOA poll.
    assert_eq!(
        app.read_counter("bindizr_xfr_total", &ixfr_truncated).await,
        truncated + 1.0
    );
    assert_eq!(
        app.read_counter("bindizr_soa_queries_total", &[r#"result="ok""#])
            .await,
        soa_ok
    );
}

/// Verify that IXFR serial ordering selects SOA-only replies for ordinary and catalog zones on
/// both transports.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn ixfr_serial_order_selects_soa_only_replies() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let key = tsig::create_tsig_key(&app, "ixfr-serial-key", KeyRole::Admin).await;

    let mut mismatches = Vec::new();

    for (zone_name, full_count) in [(zone["name"].as_str().unwrap(), 3), ("catalog.bindizr", 5)] {
        let response =
            dns::exchange_dns_query(app.dns_port(), zone_name, Rtype::SOA.to_int()).unwrap();
        let soa = response
            .answer()
            .unwrap()
            .limit_to::<Soa<_>>()
            .next()
            .unwrap()
            .unwrap();
        let current = soa.data().serial().into_int();

        // RFC 1982, Section 3.2: half-range is undefined; larger distances wrap.
        // RFC 1995, Section 2: newer clients receive the current SOA only.
        for (client_serial, soa_only) in [
            (current, true),
            (current + 1, true),
            (current.wrapping_add(0x7fff_ffff), true),
            (current.wrapping_add(0x8000_0000), false),
            (current.wrapping_add(0x8000_0001), false),
            (current - 1, false),
            (u32::MAX, false),
        ] {
            for key in [None, Some(&key)] {
                for udp in [false, true] {
                    let query = dns::build_ixfr_query(zone_name, client_serial);
                    let response = dns::exchange_request(query, key, |message| {
                        if udp {
                            dns::exchange_udp(app.dns_port(), message)
                        } else {
                            dns::exchange_tcp(app.dns_port(), message)
                        }
                    })
                    .unwrap();

                    assert_eq!(response.header().rcode(), Rcode::NOERROR);
                    assert_eq!(response.header().id(), 1995);
                    assert!(response.header().aa() && !response.header().tc());
                    assert_eq!(response.sole_question().unwrap().qtype(), Rtype::IXFR);
                    let answers: Vec<_> = response.answer().unwrap().map(Result::unwrap).collect();
                    let first = answers[0].to_record::<Soa<_>>().unwrap().unwrap();

                    assert_eq!(first.data(), soa.data());
                    assert_eq!(first.ttl(), soa.ttl());
                    let expected_count = if soa_only || udp {
                        1
                    } else {
                        full_count
                    };

                    if answers.len() != expected_count {
                        mismatches.push((
                            zone_name,
                            client_serial,
                            key.is_some(),
                            udp,
                            answers.len(),
                        ));
                    }

                    if !soa_only && !udp {
                        let last = answers
                            .last()
                            .unwrap()
                            .to_record::<Soa<_>>()
                            .unwrap()
                            .unwrap();

                        assert_eq!(last.data(), soa.data());
                    }
                }
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "zone, client serial, signed, UDP, answers: {mismatches:?}"
    );
}

/// Verify that transfer permission is required even when IXFR would return only an SOA.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn ixfr_soa_only_replies_require_transfer_permission() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let key = tsig::create_tsig_key(&app, "ixfr-ungranted-key", KeyRole::Own).await;

    let current = u32::try_from(zone["serial"].as_u64().unwrap()).unwrap();

    for zone_name in [zone["name"].as_str().unwrap(), "catalog.bindizr"] {
        for serial in [current, current + 1] {
            for udp in [false, true] {
                let query = dns::build_ixfr_query(zone_name, serial);
                let response = dns::exchange_request(query, Some(&key), |message| {
                    if udp {
                        dns::exchange_udp(app.dns_port(), message)
                    } else {
                        dns::exchange_tcp(app.dns_port(), message)
                    }
                })
                .unwrap();

                assert_eq!(response.header().rcode(), Rcode::REFUSED);
                assert_eq!(response.header_counts().ancount(), 0);
            }
        }
    }
}

/// Verify that local SOA diagnostics do not exempt UDP IXFR from the transfer address ACL.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn unsigned_local_ixfr_requires_a_registered_secondary() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let serial = u32::try_from(zone["serial"].as_u64().unwrap()).unwrap();

    for registered in [false, true] {
        if registered {
            app.create_secondary("loopback", "127.0.0.1").await;
        }

        for qtype in [Rtype::SOA, Rtype::IXFR, Rtype::AXFR] {
            let query = if qtype == Rtype::IXFR {
                dns::build_ixfr_query(zone_name, serial).finish()
            } else {
                common::build_edns_query(zone_name, qtype, &[]).finish()
            };

            for response in [
                dns::exchange_udp(app.dns_port(), &query).unwrap(),
                dns::exchange_tcp(app.dns_port(), &query).unwrap(),
            ] {
                let response = Message::from_octets(response).unwrap();
                let expected = if registered || qtype == Rtype::SOA {
                    Rcode::NOERROR
                } else {
                    Rcode::REFUSED
                };

                assert_eq!(
                    response.header().rcode(),
                    expected,
                    "{qtype}, registered={registered}"
                );
            }
        }
    }
}

/// Verify that an unsigned transfer still runs under the address acl.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn unsigned_transfer_enforces_address_acl() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, None).unwrap();

    assert!(
        outcome.records() >= 3,
        "the zone carries its SOA twice plus NS"
    );
}

/// Verify that a signed transfer answers under the key that asked.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn signed_transfer_replies_with_request_key() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "xfr-admin-key", KeyRole::Admin).await;

    // `axfr` verifies every envelope's MAC, so an unsigned answer — which BIND
    // discards as "expected a TSIG" — fails here rather than passing silently.
    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, Some(&key)).unwrap();

    assert!(outcome.records() >= 3);
}

/// Verify that a key transfers only the zones its role grants `zone:transfer` in.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn signed_transfer_limits_zones_to_key_role_grants() {
    let app = transfer_app().await;
    let granted_zone = app.create_test_zone().await;
    let granted_zone_name = granted_zone["name"].as_str().unwrap();
    let narrowed_zone_name = app.zone_name("narrowed.example");

    app.create_zone_cli(&narrowed_zone_name, "3600").await;

    let ungranted_zone_name = app.zone_name("ungranted.example");

    app.create_zone_cli(&ungranted_zone_name, "3600").await;

    let key = tsig::create_tsig_key(&app, "xfr-scoped-key", KeyRole::Own).await;
    app.run_cli_success(
        &[
            "role",
            "grant",
            &key.name,
            "--zone",
            granted_zone_name,
            "--actions",
            "zone:transfer",
        ],
        None,
    )
    .await;

    // Reading a zone's records is not transferring it.
    app.run_cli_success(
        &[
            "role",
            "grant",
            &key.name,
            "--zone",
            &narrowed_zone_name,
            "--actions",
            "record:read",
        ],
        None,
    )
    .await;

    let outcome = dns::fetch_axfr_tcp(app.dns_port(), granted_zone_name, Some(&key)).unwrap();

    assert!(outcome.records() >= 3);

    for zone_name in [&narrowed_zone_name, &ungranted_zone_name] {
        let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, Some(&key)).unwrap();

        assert_eq!(outcome.refusal(), Rcode::REFUSED, "zone {zone_name}");
    }
}

/// Verify that a transfer only grant pulls the zone without changing it.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn transfer_only_grant_reads_zone_without_write_access() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "xfr-transfer-key", KeyRole::Own).await;
    app.run_cli_success(
        &[
            "role",
            "grant",
            &key.name,
            "--zone",
            zone_name,
            "--actions",
            "zone:transfer",
        ],
        None,
    )
    .await;

    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, Some(&key)).unwrap();

    assert!(outcome.records() >= 3);

    // The same key must not be able to write what it just read.
    let rcode = nsupdate::send_update_udp(
        app.dns_port(),
        zone_name,
        &[],
        &[UpdateRecord::AddA {
            name: format!("www.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.80".to_string(),
        }],
        Some(&key),
    )
    .unwrap();

    assert_eq!(rcode, Rcode::REFUSED);
}

/// Verify that an unknown key is refused rather than falling back to the address.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn signed_transfer_rejects_unknown_key_without_address_fallback() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The address would have been allowed; signing with a key bindizr does not
    // hold must not be a way around the check.
    let stranger = SigningKey {
        name: "stranger-key".to_string(),
        algorithm: Algorithm::Sha256,
        secret: "c3RyYW5nZXItc2VjcmV0LW1hdGVyaWFsLWZvci10ZXN0cw==".to_string(),
    };
    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, Some(&stranger));

    assert!(
        outcome.is_err() || matches!(outcome, Ok(TransferResult::Refused { .. })),
        "an unknown key was accepted: {outcome:?}"
    );
}

/// Verify that signed zone propagates DNSSEC records and signed IXFR.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn signed_zone_propagates_dnssec_records_and_signed_ixfr() {
    let app = TestApp::start().await;

    // Only the compose stack runs BIND9 secondaries to observe.
    if !app.has_dns_secondaries() {
        return;
    }

    // Phase 1: an unsigned zone with one A record, propagated to both
    // secondaries by the harness's post-mutation DNS verification.
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap().to_string();

    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www",
                "type": "A",
                "value": "192.0.2.10",
                "zone_name": zone_name
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);

    // Phase 2: enable DNSSEC.
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"] })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);

    // Phase 3: the signed view reaches both secondaries. Explicit-type
    // queries return DNSSEC records without the DO bit.
    for port in app.dns_secondary_ports() {
        dns::wait_for_any_dns_record(*port, &zone_name, Rtype::DNSKEY.to_int()).await;
        dns::wait_for_any_dns_record(*port, &zone_name, Rtype::RRSIG.to_int()).await;
    }

    // Phase 4: mutation re-signs the zone in one transaction; verifying the new
    // A record on both secondaries exercises the signed IXFR delta.
    let base_serial = app.read_zone_serial(&zone_name).await;

    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "api",
                "type": "A",
                "value": "192.0.2.11",
                "zone_name": zone_name
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(app.read_zone_serial(&zone_name).await, base_serial + 1);

    // Phase 5: both secondaries converge on the bumped serial.
    let mut attempts = 0;

    loop {
        let (_, body) = app
            .send_request(Method::GET, &format!("/zones/{zone_name}/status"), None)
            .await;
        let all_in_sync = body["secondaries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|secondary| secondary["status"] == "in_sync");

        if all_in_sync {
            break;
        }

        attempts += 1;

        assert!(attempts < 60, "secondaries never reached in_sync: {body}");

        time::sleep(Duration::from_secs(1)).await;
    }
}

/// Verify that NSEC3 zone propagates nsec3param and CDS.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn nsec3_zone_propagates_nsec3param_and_cds() {
    let app = TestApp::start().await;

    // Only the compose stack runs BIND9 secondaries to observe.
    if !app.has_dns_secondaries() {
        return;
    }

    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap().to_string();

    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www",
                "type": "A",
                "value": "192.0.2.10",
                "zone_name": zone_name
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);

    let policy_name = format!("{}-nsec3", app.namespace());

    let (status, _) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name, "denial": "nsec3" })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy_name": policy_name, "parent_ns_addrs": ["127.0.0.1:9"] })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);

    // NSEC3PARAM at the apex shows the NSEC3 denial plane transferred; CDS
    // (RFC 7344) shows the derived key record set plane did too.
    for port in app.dns_secondary_ports() {
        dns::wait_for_any_dns_record(*port, &zone_name, Rtype::NSEC3PARAM.to_int()).await;
        dns::wait_for_any_dns_record(*port, &zone_name, Rtype::CDS.to_int()).await;
    }
}

/// Verify that an IXFR across a forced serial bump of an unsigned zone is answered
/// as a delta: the bump journals its SOA pair, so the step is no gap.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn ixfr_steps_across_a_forced_serial_bump() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Enough records that the bump's two journal rows are smaller than the zone
    // (RFC 1995, Section 2 lets a larger delta go out as AXFR).
    for index in 0..4 {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": format!("host{index}"), "type": "A", "value": "192.0.2.1",
                    "zone_name": zone_name
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    let before = u32::try_from(app.read_zone_serial(zone_name).await).unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/notify?bump_serial=true"),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    // Registered after the bump, whose NOTIFY no listener here would answer.
    app.create_secondary("loopback", "127.0.0.1").await;

    let response =
        dns::exchange_request(dns::build_ixfr_query(zone_name, before), None, |message| {
            dns::exchange_tcp(app.dns_port(), message)
        })
        .unwrap();

    assert_eq!(response.header().rcode(), Rcode::NOERROR);

    let body = common::wait_for_transfer_log(&app, "secondary_name=loopback", 1).await;

    assert_eq!(body["items"][0]["kind"], "ixfr", "{body}");
    assert_eq!(body["items"][0]["incremental"], true, "{body}");
}

/// Verify that the transfer log lists served and refused transfers by address and by
/// secondary, a refusal to an address no secondary had included.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn transfer_log_lists_transfers_by_client_ip_and_secondary() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Refused while no secondary has the address; the log shows it by address.
    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, None).unwrap();

    assert_eq!(outcome.refusal(), Rcode::REFUSED);

    let body = common::wait_for_transfer_log(&app, "client_ip=127.0.0.1&sort=created_at", 1).await;

    assert_eq!(body["items"][0]["zone_name"], zone_name, "{body}");
    assert_eq!(body["items"][0]["kind"], "axfr");
    assert_eq!(body["items"][0]["result"], "refused");
    assert!(body["items"][0]["serial"].is_null(), "{body}");
    assert!(!body["items"][0]["error_code"].is_null(), "{body}");
    assert!(body["items"][0]["created_at"].is_string(), "{body}");

    app.create_secondary("loopback", "127.0.0.1").await;

    let outcome = dns::fetch_axfr_tcp(app.dns_port(), zone_name, None).unwrap();

    assert!(outcome.records() >= 3);

    // Rows key by address, so the secondary registered afterwards reads both.
    let body = common::wait_for_transfer_log(&app, "secondary_name=loopback", 2).await;

    assert_eq!(body["items"][0]["kind"], "axfr", "{body}");
    assert_eq!(body["items"][0]["result"], "ok");
    assert_eq!(body["items"][0]["transport"], "tcp");
    assert_eq!(body["items"][0]["incremental"], false);
    assert_eq!(body["items"][0]["serial"], zone["serial"], "{body}");
    assert!(body["items"][0]["error_code"].is_null(), "{body}");
    assert_eq!(body["items"][0]["client_ip"], "127.0.0.1");
    assert_eq!(body["items"][1]["result"], "refused", "{body}");

    for (query, expected) in [
        ("result=refused".to_string(), 1),
        ("until=2000-01-01T00:00:00Z".to_string(), 0),
        ("zone_name=other.example".to_string(), 0),
        // The filter is a zone name, so the absolute spelling selects the same rows.
        (format!("zone_name={zone_name}."), 2),
        ("client_ip=192.0.2.1".to_string(), 0),
        ("secondary_name=loopback&client_ip=192.0.2.1".to_string(), 0),
    ] {
        let (status, body) = app
            .send_request(Method::GET, &format!("/logs/transfer?{query}"), None)
            .await;

        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        assert_eq!(body["pagination"]["total"], expected, "{query}: {body}");
    }

    for (query, status, code) in [
        (
            "since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z",
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
        ),
        ("zone_name=*", StatusCode::BAD_REQUEST, "INVALID_ZONE_FIELD"),
        ("result=served", StatusCode::BAD_REQUEST, "INVALID_INPUT"),
        (
            "client_ip=loopback",
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
        ),
        (
            "secondary_name=missing",
            StatusCode::NOT_FOUND,
            "SECONDARY_NOT_FOUND",
        ),
    ] {
        let (actual, body) = app
            .send_request(Method::GET, &format!("/logs/transfer?{query}"), None)
            .await;

        assert_eq!(actual, status, "{query}: {body}");
        assert_eq!(body["code"], code, "{query}: {body}");
    }

    // The zone's status carries the same transfer beside the probe, which
    // finds nothing listening on the registered address.
    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/status"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["secondaries"][0]["last_transfer"]["kind"], "axfr",
        "{body}"
    );
    assert_eq!(
        body["secondaries"][0]["last_transfer"]["serial"], zone["serial"],
        "{body}"
    );

    let listed = app
        .run_cli_success(&["log", "transfer", "--secondary", "loopback"], None)
        .await;

    assert!(
        listed.contains(zone_name) && listed.contains("AXFR") && listed.contains("refused"),
        "{listed}"
    );

    // The check fails, since nothing answers on the registered address, but
    // still reports how each zone was last served.
    let checked = app.run_cli(&["secondary", "check", "loopback"], None).await;
    let stdout = String::from_utf8_lossy(&checked.stdout);

    assert!(stdout.contains("Transfers: 1 zones:"), "{stdout}");
}

/// Verify that a malformed TSIG gets unsigned FORMERR even from an allowed address
/// (RFC 8945, Section 5.2).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn malformed_tsig_returns_unsigned_formerr() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "xfr-malformed-key", KeyRole::Admin).await;

    let qname = dns::parse_name(zone_name).unwrap();

    // A valid signature, then one more record: the TSIG is no longer last.
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(41);
    let mut question = builder.question();
    question.push((&qname, Rtype::AXFR)).unwrap();
    let mut additional = question.additional();
    ClientSequence::request(key.to_tsig_key().unwrap(), &mut additional, Time48::now()).unwrap();
    additional
        .push((
            &qname,
            Class::IN,
            Ttl::ZERO,
            A::from_str("192.0.2.1").unwrap(),
        ))
        .unwrap();
    let not_last = additional.finish();

    // A TSIG whose 4-octet MAC is below the floor of RFC 8945, Section 5.2.2.1.
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(42);
    let mut question = builder.question();
    question.push((&qname, Rtype::AXFR)).unwrap();
    let mut additional = question.additional();
    let algorithm = dns::parse_name("hmac-sha256.").unwrap();
    let tsig = Tsig::new(
        algorithm,
        Time48::now(),
        300,
        vec![0; 4],
        42,
        TsigRcode::NOERROR,
        Vec::new(),
    )
    .unwrap();
    additional
        .push((
            dns::parse_name(&key.name).unwrap(),
            Class::ANY,
            Ttl::ZERO,
            tsig,
        ))
        .unwrap();
    let short_mac = additional.finish();

    for (label, query) in [("not last", not_last), ("short MAC", short_mac)] {
        let response = dns::exchange_tcp(app.dns_port(), &query)
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        let response = Message::from_octets(response).unwrap();

        assert_eq!(response.header().rcode(), Rcode::FORMERR, "{label}");
        assert_eq!(
            response.additional().unwrap().count(),
            0,
            "{label}: a FORMERR for a malformed TSIG is signed by no one"
        );
    }
}

/// Verify that a response copies the query's RD bit (RFC 1035, Section 4.1.1).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn query_response_preserves_rd_bit() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for rd in [true, false] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(77);
        builder.header_mut().set_rd(rd);
        let mut question = builder.question();
        question
            .push((&dns::parse_name(zone_name).unwrap(), Rtype::SOA))
            .unwrap();
        let response = dns::exchange_udp(app.dns_port(), &question.finish()).unwrap();
        let response = Message::from_octets(response).unwrap();

        assert_eq!(response.header().rcode(), Rcode::NOERROR);
        assert_eq!(response.header().rd(), rd, "rd={rd}");
    }
}

/// Verify that multiple questions are rejected before a handler is chosen or EDNS versions are
/// checked.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn multi_question_queries_receive_formerr() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "multi-question-key", KeyRole::Admin).await;

    // RFC 9619, Section 4 requires FORMERR for QUERY with QDCOUNT > 1.
    for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR, Rtype::A] {
        for qclass in [Class::IN, Class::CH] {
            for version in [None, Some(0), Some(1)] {
                for key in [None, Some(&key)] {
                    for udp in [false, true] {
                        let query =
                            common::build_multi_question_query(zone_name, qtype, qclass, version);
                        let response = dns::exchange_request(query, key, |message| {
                            if udp {
                                dns::exchange_udp(app.dns_port(), message)
                            } else {
                                dns::exchange_tcp(app.dns_port(), message)
                            }
                        })
                        .unwrap();

                        assert_eq!(
                            response.header().rcode(),
                            Rcode::FORMERR,
                            "{qtype} {qclass} EDNS {version:?} signed={} UDP={udp}",
                            key.is_some()
                        );
                        assert_eq!(response.header().id(), 9619);
                        assert!(response.header().qr() && response.header().rd());
                        assert!(!response.header().aa() && !response.header().tc());
                        assert_eq!(response.header_counts().ancount(), 0);
                        assert_eq!(response.header_counts().nscount(), 0);
                        assert_eq!(response.sole_question().unwrap().qtype(), qtype);
                        assert_eq!(response.sole_question().unwrap().qclass(), qclass);
                        assert_eq!(response.opt().is_some(), version.is_some());

                        if let Some(opt) = response.opt() {
                            assert_eq!(opt.rcode(response.header()), OptRcode::FORMERR);
                            assert_eq!(opt.version(), 0);
                            assert!(opt.dnssec_ok());
                        }
                    }
                }
            }
        }
    }
}

/// Verify that a QUERY whose question cannot be read receives a header-only FORMERR:
/// none (RFC 9619, Section 4), an unreadable one, or more than one.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn queries_without_a_readable_question_receive_formerr() {
    let app = TestApp::start_local().await;

    for count in [0u16, 1, 2, u16::MAX] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(9619);
        builder.header_mut().set_rd(true);
        let mut wire = builder.question().finish();
        wire[4..6].copy_from_slice(&count.to_be_bytes());

        for body in [&[][..], &[0xc0, 0x0c][..]] {
            let mut query = wire.clone();
            query.extend_from_slice(body);

            for response in [
                dns::exchange_udp(app.dns_port(), &query).unwrap(),
                dns::exchange_tcp(app.dns_port(), &query).unwrap(),
            ] {
                let response = Message::from_octets(response).unwrap();

                assert_eq!(response.header().id(), 9619);
                assert_eq!(response.header().rcode(), Rcode::FORMERR);
                assert!(response.header().qr() && response.header().rd());
                assert_eq!(response.header_counts().qdcount(), 0);
                assert_eq!(response.header_counts().ancount(), 0);
                assert_eq!(response.header_counts().nscount(), 0);
                assert_eq!(response.header_counts().arcount(), 0);
            }
        }
    }
}

/// Verify that a signed SOA answer names its signatures under the same owner
/// as the SOA, whatever case the question spelled the zone in.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn soa_signatures_share_the_soa_owner() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"] })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let query = common::build_edns_query(&zone_name.to_uppercase(), Rtype::SOA, &[(0, true)]);
    let response = dns::exchange_request(query, None, |message| {
        dns::exchange_tcp(app.dns_port(), message)
    })
    .unwrap();
    let owners: Vec<(Rtype, String)> = response
        .answer()
        .unwrap()
        .map(|record| {
            let record = record.unwrap();
            (record.rtype(), record.owner().to_string())
        })
        .collect();

    assert!(
        owners.iter().any(|(rtype, _)| *rtype == Rtype::RRSIG),
        "{owners:?}"
    );
    assert!(
        owners.iter().all(|(_, owner)| owner == zone_name),
        "{owners:?}"
    );
}

/// Verify that DO is echoed in ordinary, truncated, refused and BADVERS responses.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn query_response_preserves_edns_dnssec_ok() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "dnssec-ok-key", KeyRole::Admin).await;

    // RFC 3225, Section 3 requires the response to copy the query's DO bit.
    for dnssec_ok in [true, false] {
        for version in [0, 1] {
            for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR, Rtype::A] {
                for key in [None, Some(&key)] {
                    for udp in [false, true] {
                        let query =
                            common::build_edns_query(zone_name, qtype, &[(version, dnssec_ok)]);
                        let response = dns::exchange_request(query, key, |message| {
                            if udp {
                                dns::exchange_udp(app.dns_port(), message)
                            } else {
                                dns::exchange_tcp(app.dns_port(), message)
                            }
                        })
                        .unwrap();
                        let opt = response.opt().unwrap();

                        assert_eq!(
                            opt.dnssec_ok(),
                            dnssec_ok,
                            "{qtype} EDNS={version} signed={} UDP={udp}",
                            key.is_some()
                        );
                        let expected = if version != 0 {
                            OptRcode::BADVERS
                        } else if qtype == Rtype::A {
                            OptRcode::REFUSED
                        } else {
                            OptRcode::NOERROR
                        };

                        assert_eq!(opt.rcode(response.header()), expected);
                        assert_eq!(opt.version(), 0);
                        assert_eq!(opt.udp_payload_size(), 1232);
                        assert_eq!(
                            response.header().tc(),
                            udp && qtype == Rtype::AXFR && version == 0
                        );
                    }
                }
            }
        }
    }
}

/// Verify that DO is preserved when TSIG verification rejects a key or MAC.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn query_tsig_error_preserves_edns_dnssec_ok() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "dnssec-ok-error-key", KeyRole::Admin).await;

    for dnssec_ok in [false, true] {
        for rcode in [TsigRcode::BADKEY, TsigRcode::BADSIG] {
            let mut signing_key = key.clone();

            if rcode == TsigRcode::BADKEY {
                signing_key.name = "unknown-key".to_string();
            }

            let mut query = common::build_edns_query(zone_name, Rtype::SOA, &[(0, dnssec_ok)]);
            tsig::sign(&mut query, &signing_key).unwrap();
            let mut query = query.finish();

            if rcode == TsigRcode::BADSIG {
                let mac_end = query.len() - 7;
                query[mac_end] ^= 0xff;
            }

            for response in [
                dns::exchange_udp(app.dns_port(), &query).unwrap(),
                dns::exchange_tcp(app.dns_port(), &query).unwrap(),
            ] {
                let response = Message::from_octets(response).unwrap();

                assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
                assert_eq!(response.opt().unwrap().dnssec_ok(), dnssec_ok);
                let tsig = response
                    .additional()
                    .unwrap()
                    .limit_to::<Tsig<_, _>>()
                    .last()
                    .unwrap()
                    .unwrap();

                assert_eq!(tsig.data().error(), rcode);
                assert!(tsig.data().mac().is_empty());
            }
        }
    }
}

/// Verify that stale TCP and UDP queries receive an authenticated BADTIME with OPT.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn badtime_query_responses_preserve_edns_and_verify() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "badtime-query-key", KeyRole::Admin).await;

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
            let before = Time48::now();

            for response in [
                dns::exchange_udp(app.dns_port(), &query).unwrap(),
                dns::exchange_tcp(app.dns_port(), &query).unwrap(),
            ] {
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
                let server_time = tsig.data().other_time().unwrap();

                assert!(server_time >= before && server_time <= Time48::now());
                tsig::verify_response_mac(&query, &response, &key).unwrap();

                // The MAC covers both OPT flags and the server's six-byte time.
                let opt_flags = response.additional().unwrap().pos() + 7;

                for offset in [opt_flags, response.as_slice().len() - 1] {
                    let mut tampered = response.as_slice().to_vec();
                    tampered[offset] ^= 1;
                    assert!(
                        tsig::verify_response_mac(
                            &query,
                            &Message::from_octets(tampered).unwrap(),
                            &key
                        )
                        .is_err()
                    );
                }
            }
        }
    }
}

/// Verify that truncated queries are authenticated before time and length policy applies.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn truncated_queries_follow_tsig_validation_order() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "truncated-query-key", KeyRole::Admin).await;

    for dnssec_ok in [false, true] {
        for qtype in [Rtype::SOA, Rtype::AXFR, Rtype::IXFR] {
            for (age, corrupt, expected) in [
                (0, false, TsigRcode::BADTRUNC),
                (3600, false, TsigRcode::BADTIME),
                (0, true, TsigRcode::BADSIG),
                (3600, true, TsigRcode::BADSIG),
            ] {
                let signed_at = Time48::from_u64(u64::from(Time48::now()) - age);
                let mut query = common::build_edns_query(zone_name, qtype, &[(0, dnssec_ok)]);
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
                    dns::exchange_udp(app.dns_port(), &query).unwrap(),
                    dns::exchange_tcp(app.dns_port(), &query).unwrap(),
                ] {
                    let response = Message::from_octets(response).unwrap();

                    assert_eq!(response.header().id(), 3225);
                    assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
                    assert_eq!(response.opt().unwrap().dnssec_ok(), dnssec_ok);
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
    }
}

/// Verify that OPT handling follows RFC 6891, Sections 6.1.1 and 6.1.3, and that
/// an AXFR envelope carries the OPT too (RFC 9103, Section 6.3.4).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn edns_query_returns_opt() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let plain = dns::exchange_udp(
        app.dns_port(),
        &common::build_edns_query(zone_name, Rtype::SOA, &[]).finish(),
    )
    .unwrap();
    let plain = Message::from_octets(plain).unwrap();

    assert_eq!(plain.header().rcode(), Rcode::NOERROR);
    assert!(plain.opt().is_none(), "no OPT was asked for");

    let edns = dns::exchange_udp(
        app.dns_port(),
        &common::build_edns_query(zone_name, Rtype::SOA, &[(0, false)]).finish(),
    )
    .unwrap();
    let edns = Message::from_octets(edns).unwrap();

    assert_eq!(edns.header().rcode(), Rcode::NOERROR);
    let opt = edns.opt().unwrap();

    assert_eq!(opt.version(), 0);
    assert_eq!(opt.udp_payload_size(), 1232);

    let doubled = dns::exchange_udp(
        app.dns_port(),
        &common::build_edns_query(zone_name, Rtype::SOA, &[(0, false); 2]).finish(),
    )
    .unwrap();
    let doubled = Message::from_octets(doubled).unwrap();

    assert_eq!(doubled.header().rcode(), Rcode::FORMERR);

    let newer = dns::exchange_udp(
        app.dns_port(),
        &common::build_edns_query(zone_name, Rtype::SOA, &[(1, false)]).finish(),
    )
    .unwrap();
    let newer = Message::from_octets(newer).unwrap();
    let opt = newer.opt().unwrap();

    assert_eq!(opt.rcode(newer.header()), OptRcode::BADVERS);
    assert_eq!(opt.version(), 0);

    let response = dns::exchange_tcp(
        app.dns_port(),
        &common::build_edns_query(zone_name, Rtype::AXFR, &[(0, false)]).finish(),
    )
    .unwrap();
    let response = Message::from_octets(response).unwrap();

    assert_eq!(response.header().rcode(), Rcode::NOERROR);

    // RFC 7828, Section 3.3.2: over TCP the OPT carries the idle timeout.
    let keepalive = response.opt().unwrap().opt().tcp_keepalive().unwrap();

    assert_eq!(keepalive.timeout().map(u16::from), Some(300));
    assert!(edns.opt().unwrap().opt().tcp_keepalive().is_none());
}

/// Verify that a UDP answer over 512 octets is truncated without EDNS and
/// sent whole within an advertised size (RFC 1035, Section 4.2.1).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn udp_query_truncates_answers_above_limit() {
    let app = transfer_app().await;

    // Three 60-octet labels push the SOA answer well past 512 octets.
    let label = "x".repeat(60);
    let zone_name = format!("{label}.{label}.{label}.{}", app.zone_name("long.test"));

    let (status, body) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": format!("hostmaster@{zone_name}"),
                "default_ttl": 3600,
                "serial": 10,
                "refresh": 7200,
                "retry": 3600,
                "expire": 604_800,
                "minimum_ttl": 86400
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let plain = dns::exchange_udp(
        app.dns_port(),
        &common::build_edns_query(&zone_name, Rtype::SOA, &[]).finish(),
    )
    .unwrap();
    let plain = Message::from_octets(plain).unwrap();

    assert!(plain.header().tc(), "over 512 octets without EDNS");
    assert_eq!(plain.header_counts().ancount(), 0);
    assert!(plain.as_slice().len() <= 512);

    let edns = dns::exchange_udp(
        app.dns_port(),
        &common::build_edns_query(&zone_name, Rtype::SOA, &[(0, false)]).finish(),
    )
    .unwrap();
    let edns = Message::from_octets(edns).unwrap();

    assert!(!edns.header().tc(), "fits the advertised size");
    assert_eq!(edns.header_counts().ancount(), 1);
}

/// Verify that two transfers pipelined on one connection both complete,
/// their streams free to intermingle (RFC 9103, Section 6.2).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tcp_connection_completes_pipelined_transfers() {
    let app = transfer_app().await;
    let first_zone = app.create_test_zone().await;
    let first_zone_name = first_zone["name"].as_str().unwrap().to_string();
    let second_zone_name = app.zone_name("second.example");

    app.create_zone_cli(&second_zone_name, "3600").await;

    let mut stream = TcpStream::connect(("127.0.0.1", app.dns_port())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    for (id, zone_name) in [(1u16, &first_zone_name), (2u16, &second_zone_name)] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(id);
        let mut question = builder.question();
        question
            .push((&dns::parse_name(zone_name).unwrap(), Rtype::AXFR))
            .unwrap();
        let query = question.finish();
        dns::write_frame(&mut stream, &query).unwrap();
    }

    // Each transfer ends with its second SOA, whichever order the envelopes
    // of the two arrive in.
    let mut soas: HashMap<u16, usize> = HashMap::new();

    while soas.values().filter(|&&seen| seen >= 2).count() < 2 {
        let response = dns::read_frame(&mut stream).unwrap().unwrap();
        let response = Message::from_octets(response).unwrap();

        assert_eq!(response.header().rcode(), Rcode::NOERROR);
        let seen = response
            .answer()
            .unwrap()
            .filter(|record| {
                record
                    .as_ref()
                    .is_ok_and(|record| record.rtype() == Rtype::SOA)
            })
            .count();
        *soas.entry(response.header().id()).or_default() += seen;
    }

    assert_eq!(soas.get(&1), Some(&2));
    assert_eq!(soas.get(&2), Some(&2));
}

/// Verify that rejected queries do not prevent later requests on the same TCP connection.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn rejected_queries_keep_the_tcp_connection_usable() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", app.dns_port())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut malformed = common::build_edns_query(zone_name, Rtype::SOA, &[]).finish();
    malformed.truncate(12);
    malformed[4..6].copy_from_slice(&2u16.to_be_bytes());
    dns::write_frame(&mut stream, &malformed).unwrap();
    let response = dns::read_frame(&mut stream).unwrap().unwrap();

    assert_eq!(
        Message::from_octets(response).unwrap().header().rcode(),
        Rcode::FORMERR
    );

    for (opcode, qtype, qclass, expected) in [
        (Opcode::STATUS, Rtype::SOA, Class::IN, Rcode::NOTIMP),
        (Opcode::QUERY, Rtype::A, Class::IN, Rcode::REFUSED),
        (Opcode::QUERY, Rtype::SOA, Class::CH, Rcode::NOTAUTH),
    ] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(1234);
        builder.header_mut().set_opcode(opcode);
        let mut question = builder.question();
        question
            .push((&dns::parse_name(zone_name).unwrap(), qtype, qclass))
            .unwrap();
        dns::write_frame(&mut stream, &question.finish()).unwrap();
        let response = dns::read_frame(&mut stream).unwrap().unwrap();
        let response = Message::from_octets(response).unwrap();

        assert_eq!(response.header().id(), 1234);
        assert_eq!(response.header().rcode(), expected);
        // None of these questions concerns a zone held here, so none claims
        // authority (RFC 1035, Section 4.1.1).
        assert!(
            !response.header().aa(),
            "{opcode} {qtype} {qclass} answered with AA set"
        );

        let query = common::build_edns_query(zone_name, Rtype::SOA, &[]).finish();
        dns::write_frame(&mut stream, &query).unwrap();
        let response = dns::read_frame(&mut stream).unwrap().unwrap();
        let response = Message::from_octets(response).unwrap();

        assert_eq!(response.header().rcode(), Rcode::NOERROR);
        assert_eq!(response.header_counts().ancount(), 1);
    }
}

/// Verify that a question of another class is NOTAUTH, its class echoed
/// (RFC 5936, Section 2.2.2).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn query_returns_notauth_for_unsupported_class() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(95);
    let mut question = builder.question();
    question
        .push((&dns::parse_name(zone_name).unwrap(), Rtype::SOA, Class::CH))
        .unwrap();

    let response = dns::exchange_udp(app.dns_port(), &question.finish()).unwrap();
    let response = Message::from_octets(response).unwrap();

    assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
    assert_eq!(response.first_question().unwrap().qclass(), Class::CH);

    // RFC 8945, Section 5.3: a signed question hears its NOTAUTH under the key.
    let key = tsig::create_tsig_key(&app, "class-key", KeyRole::Admin).await;

    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(96);
    let mut question = builder.question();
    question
        .push((&dns::parse_name(zone_name).unwrap(), Rtype::SOA, Class::CH))
        .unwrap();
    let mut additional = question.additional();
    tsig::sign(&mut additional, &key).unwrap();
    let response = dns::exchange_tcp(app.dns_port(), &additional.finish()).unwrap();
    let response = Message::from_octets(response).unwrap();

    assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
    assert!(tsig::parse_tsig_presence(&response).unwrap());
}

/// Verify that an IN IXFR query cannot take its client serial from another class's SOA.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn ixfr_rejects_foreign_soa_classes() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let serial = u32::try_from(zone["serial"].as_u64().unwrap()).unwrap();

    app.create_secondary("class-loopback", "127.0.0.1").await;
    let key = tsig::create_tsig_key(&app, "ixfr-record-class", KeyRole::Admin).await;

    let qname = dns::parse_name(zone_name).unwrap();

    for class in [
        Class::IN,
        Class::CH,
        Class::HS,
        Class::ANY,
        Class::NONE,
        Class::from_int(0),
        Class::from_int(2),
        Class::from_int(65280),
        Class::from_int(u16::MAX),
    ] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(1995);
        let mut question = builder.question();
        question.push((&qname, Rtype::IXFR, Class::IN)).unwrap();
        let mut authority = question.authority();
        authority
            .push((
                &qname,
                class,
                Ttl::ZERO,
                Soa::new(
                    qname.clone(),
                    qname.clone(),
                    Serial::from(serial),
                    Ttl::ZERO,
                    Ttl::ZERO,
                    Ttl::ZERO,
                    Ttl::ZERO,
                ),
            ))
            .unwrap();
        let mut query = authority.additional();
        query
            .opt(|opt| {
                opt.set_udp_payload_size(512);
                opt.set_dnssec_ok(true);
                Ok(())
            })
            .unwrap();

        for key in [None, Some(&key)] {
            // A successful TLS transfer needs a key as well as the registered address.
            if class == Class::IN && key.is_none() {
                continue;
            }

            for response in [
                dns::exchange_request(query.clone(), key, |message| {
                    dns::exchange_udp(app.dns_port(), message)
                }),
                dns::exchange_request(query.clone(), key, |message| {
                    dns::exchange_tcp(app.dns_port(), message)
                }),
                dns::exchange_request(query.clone(), key, |message| {
                    dns::exchange_tls(app.dns_tls_port(), message, dns::dot_client(&app))
                }),
            ] {
                let response = response.unwrap();

                assert_eq!(response.header().id(), 1995);
                assert_eq!(
                    response.header().rcode(),
                    if class == Class::IN {
                        Rcode::NOERROR
                    } else {
                        Rcode::FORMERR
                    },
                    "{class}"
                );
                assert_eq!(response.sole_question().unwrap().qclass(), Class::IN);
                assert!(response.opt().unwrap().dnssec_ok());
                assert_eq!(
                    response.header_counts().ancount(),
                    if class == Class::IN {
                        1
                    } else {
                        0
                    }
                );
                assert!(response.as_slice().len() <= 512);
            }
        }
    }
}

/// The message section that carries the foreign-class record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional,
}

/// Build a query with a foreign-class record after a valid IN SOA where applicable.
fn build_query_with_foreign_record(
    section: Section,
    questions: usize,
    version: u8,
) -> AdditionalBuilder<Vec<u8>> {
    let qname = dns::parse_name("example.com").unwrap();
    let soa = Soa::new(
        qname.clone(),
        qname.clone(),
        Serial::from(1),
        Ttl::ZERO,
        Ttl::ZERO,
        Ttl::ZERO,
        Ttl::ZERO,
    );
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(1035);
    let mut question = builder.question();

    for _ in 0..questions {
        question.push((&qname, Rtype::SOA, Class::IN)).unwrap();
    }

    let mut answer = question.answer();

    if section == Section::Answer {
        answer.push((&qname, Class::CH, Ttl::ZERO, &soa)).unwrap();
    }

    let mut authority = answer.authority();
    authority
        .push((&qname, Class::IN, Ttl::ZERO, &soa))
        .unwrap();

    if section == Section::Authority {
        authority
            .push((&qname, Class::CH, Ttl::ZERO, &soa))
            .unwrap();
    }

    let mut additional = authority.additional();

    if section == Section::Additional {
        additional
            .push((&qname, Class::CH, Ttl::ZERO, &soa))
            .unwrap();
    }

    additional
        .opt(|opt| {
            opt.set_udp_payload_size(512);
            opt.set_dnssec_ok(true);
            opt.set_version(version);
            Ok(())
        })
        .unwrap();

    additional
}

/// Verify that every ordinary QUERY section is IN-only and that count and EDNS errors keep
/// their order.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn queries_reject_foreign_classes_in_every_section() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let key = tsig::create_tsig_key(&app, "query-record-class", KeyRole::Admin).await;

    for section in [Section::Answer, Section::Authority, Section::Additional] {
        for questions in [1, 2] {
            for version in [0, 1] {
                let query = build_query_with_foreign_record(section, questions, version);

                for key in [None, Some(&key)] {
                    for response in [
                        dns::exchange_request(query.clone(), key, |message| {
                            dns::exchange_udp(app.dns_port(), message)
                        }),
                        dns::exchange_request(query.clone(), key, |message| {
                            dns::exchange_tcp(app.dns_port(), message)
                        }),
                        dns::exchange_request(query.clone(), key, |message| {
                            dns::exchange_tls(app.dns_tls_port(), message, dns::dot_client(&app))
                        }),
                    ] {
                        let response = response.unwrap();

                        assert_eq!(
                            response.opt_rcode(),
                            if questions == 1 && version == 1 {
                                OptRcode::BADVERS
                            } else {
                                OptRcode::FORMERR
                            },
                            "{section:?} QDCOUNT={questions} EDNS={version}"
                        );
                        assert_eq!(response.sole_question().unwrap().qclass(), Class::IN);
                        assert_eq!(response.header_counts().ancount(), 0);
                        assert_eq!(response.header_counts().nscount(), 0);
                        assert!(response.opt().unwrap().dnssec_ok());
                        assert!(response.as_slice().len() <= 512);
                    }
                }
            }
        }
    }
}

/// Verify that class errors cannot bypass TSIG validation, including alongside BADVERS.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn foreign_record_classes_keep_tsig_error_precedence() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let key = tsig::create_tsig_key(&app, "bad-record-class", KeyRole::Admin).await;

    for unknown in [false, true] {
        let mut signing_key = key.clone();

        if unknown {
            signing_key.name = "unknown-record-class".to_string();
        }

        let mut query = build_query_with_foreign_record(Section::Authority, 1, 1);
        tsig::sign(&mut query, &signing_key).unwrap();
        let mut query = query.finish();

        if !unknown {
            let mac_end = query.len() - 7;
            query[mac_end] ^= 1;
        }

        for response in [
            dns::exchange_udp(app.dns_port(), &query).unwrap(),
            dns::exchange_tcp(app.dns_port(), &query).unwrap(),
            dns::exchange_tls(app.dns_tls_port(), &query, dns::dot_client(&app)).unwrap(),
        ] {
            let response = Message::from_octets(response).unwrap();

            assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
            assert!(response.opt().unwrap().dnssec_ok());
            let tsig = response
                .additional()
                .unwrap()
                .limit_to::<Tsig<_, _>>()
                .last()
                .unwrap()
                .unwrap();

            assert_eq!(
                tsig.data().error(),
                if unknown {
                    TsigRcode::BADKEY
                } else {
                    TsigRcode::BADSIG
                }
            );
            assert!(tsig.data().mac().is_empty());
        }
    }
}

/// Verify that TSIG error metrics follow the final RCODE, including overflow fallback.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_error_metrics_follow_the_encoded_response() {
    let app = TestApp::start_local().await;

    let owner = dns::parse_name(&format!(
        "{}.{}.{}.{}",
        "k".repeat(63),
        "l".repeat(63),
        "m".repeat(63),
        "n".repeat(61)
    ))
    .unwrap();
    let algorithm = dns::parse_name(&format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    ))
    .unwrap();

    for advertised in [512, 1232] {
        for (opcode, qtype) in [
            (Opcode::QUERY, Rtype::SOA),
            (Opcode::QUERY, Rtype::AXFR),
            (Opcode::QUERY, Rtype::IXFR),
            (Opcode::UPDATE, Rtype::SOA),
        ] {
            let expected = if advertised == 512 {
                Rcode::SERVFAIL
            } else {
                Rcode::NOTAUTH
            };
            let (metric, outcome) = if opcode == Opcode::UPDATE {
                (
                    "bindizr_nsupdate_requests_total",
                    if advertised == 512 {
                        "servfail"
                    } else {
                        "tsig_failed"
                    },
                )
            } else if qtype == Rtype::SOA {
                (
                    "bindizr_soa_queries_total",
                    if advertised == 512 {
                        "failed"
                    } else {
                        "refused"
                    },
                )
            } else {
                (
                    "bindizr_xfr_total",
                    if advertised == 512 {
                        "failed"
                    } else {
                        "refused"
                    },
                )
            };
            let mut labels = vec![format!(r#"result="{outcome}""#)];

            if metric == "bindizr_xfr_total" {
                labels.push(format!(r#"kind="{}""#, qtype.to_string().to_lowercase()));
                labels.push(r#"transport="udp""#.to_string());
            }

            let labels: Vec<&str> = labels.iter().map(String::as_str).collect();

            let before = app.read_counter(metric, &labels).await;

            let mut builder = MessageBuilder::new_vec();
            builder.header_mut().set_id(8945);
            builder.header_mut().set_opcode(opcode);
            let mut question = builder.question();
            question
                .push((dns::parse_name("example.com").unwrap(), qtype))
                .unwrap();
            let mut request = question.additional();
            request
                .opt(|opt| {
                    opt.set_udp_payload_size(advertised);
                    Ok(())
                })
                .unwrap();
            request
                .push((
                    &owner,
                    Class::ANY,
                    Ttl::ZERO,
                    Tsig::new(
                        algorithm.clone(),
                        Time48::now(),
                        300,
                        vec![0; 32],
                        8945,
                        TsigRcode::NOERROR,
                        Vec::new(),
                    )
                    .unwrap(),
                ))
                .unwrap();
            let response = dns::exchange_udp(app.dns_port(), &request.finish()).unwrap();
            let response = Message::from_octets(response).unwrap();

            assert_eq!(response.header().rcode(), expected);
            assert!(response.as_slice().len() <= usize::from(advertised));
            assert_eq!(app.read_counter(metric, &labels).await, before + 1.0);
        }
    }
}

/// Verify that signed UDP AXFR encoding failures count as failed transfers.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn udp_axfr_counts_encoding_failure_before_truncation() {
    let app = TestApp::start_local().await;

    let tsig_key_name = format!("{}.{}.{}.k", "d".repeat(63), "e".repeat(63), "f".repeat(63));

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({
                "name": tsig_key_name,
                "role_name": "admin",
                "algorithm": "hmac-sha512"
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    let key = SigningKey {
        name: tsig_key_name,
        secret: body["secret"].as_str().unwrap().to_string(),
        algorithm: Algorithm::Sha512,
    };
    let qname = dns::parse_name(&format!(
        "{}.{}.{}.q",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63)
    ))
    .unwrap();

    for advertised in [512, 1232] {
        let failed = [r#"kind="axfr""#, r#"transport="udp""#, r#"result="failed""#];
        let truncated = [
            r#"kind="axfr""#,
            r#"transport="udp""#,
            r#"result="truncated""#,
        ];

        let failed_before = app.read_counter("bindizr_xfr_total", &failed).await;
        let truncated_before = app.read_counter("bindizr_xfr_total", &truncated).await;

        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(5936);
        let mut question = builder.question();
        question.push((&qname, Rtype::AXFR)).unwrap();
        let mut query = question.additional();
        query
            .opt(|opt| {
                opt.set_udp_payload_size(advertised);
                Ok(())
            })
            .unwrap();
        let client =
            ClientTransaction::request(key.to_tsig_key().unwrap(), &mut query, Time48::now())
                .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socket
            .send_to(&query.finish(), ("127.0.0.1", app.dns_port()))
            .unwrap();
        let mut buffer = vec![0; 4096];
        let received = socket.recv_from(&mut buffer);

        if advertised == 512 {
            assert!(matches!(
                received,
                Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
            ));
            assert_eq!(
                app.read_counter("bindizr_xfr_total", &failed).await,
                failed_before + 1.0
            );
            assert_eq!(
                app.read_counter("bindizr_xfr_total", &truncated).await,
                truncated_before
            );
        } else {
            buffer.truncate(received.unwrap().0);
            let mut response = Message::from_octets(buffer).unwrap();

            assert!(response.header().tc());
            assert_eq!(response.header().rcode(), Rcode::NOERROR);
            client.answer(&mut response, Time48::now()).unwrap();

            assert_eq!(
                app.read_counter("bindizr_xfr_total", &failed).await,
                failed_before
            );
            assert_eq!(
                app.read_counter("bindizr_xfr_total", &truncated).await,
                truncated_before + 1.0
            );
        }
    }
}

/// Verify that a readable first question does not make a truncated later section usable.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn unreadable_bodies_receive_header_only_responses_on_every_transport() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;

    for opcode in [Opcode::QUERY, Opcode::UPDATE] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(6891);
        builder.header_mut().set_rd(true);
        builder.header_mut().set_opcode(opcode);
        let mut question = builder.question();
        question
            .push((dns::parse_name("example.com").unwrap(), Rtype::SOA))
            .unwrap();
        let complete = question.finish();
        let mut truncated_record = complete.clone();
        truncated_record[6..8].copy_from_slice(&1u16.to_be_bytes());
        let mut truncated_question = complete[..12].to_vec();
        truncated_question.extend_from_slice(&[5, b'x']);
        let mut trailing_data = complete;
        trailing_data.push(0);

        for request in [truncated_record, truncated_question, trailing_data] {
            for response in [
                dns::exchange_udp(app.dns_port(), &request).unwrap(),
                dns::exchange_tcp(app.dns_port(), &request).unwrap(),
                dns::exchange_tls(app.dns_tls_port(), &request, dns::dot_client(&app)).unwrap(),
            ] {
                let response = Message::from_octets(response).unwrap();

                assert_eq!(response.header().id(), 6891);
                assert_eq!(response.header().opcode(), opcode);
                assert!(response.header().qr() && response.header().rd());
                assert_eq!(response.header().rcode(), Rcode::FORMERR);
                assert_eq!(response.as_slice().len(), 12);
                assert_eq!(response.header_counts().qdcount(), 0);
                assert_eq!(response.header_counts().arcount(), 0);
            }
        }
    }
}

/// Verify that readable Additional sections remain meaningful when QDCOUNT is zero.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn questionless_queries_preserve_edns_and_tsig() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let key = tsig::create_tsig_key(&app, "questionless-key", KeyRole::Admin).await;

    for opcode in [Opcode::QUERY, Opcode::from_int(15)] {
        for version in [None, Some(0), Some(1)] {
            for dnssec_ok in [false, true] {
                for key in [None, Some(&key)] {
                    let mut builder = MessageBuilder::new_vec();
                    builder.header_mut().set_id(9619);
                    builder.header_mut().set_rd(true);
                    builder.header_mut().set_opcode(opcode);
                    let mut request = builder.additional();

                    if let Some(version) = version {
                        request
                            .opt(|opt| {
                                opt.set_udp_payload_size(512);
                                opt.set_version(version);
                                opt.set_dnssec_ok(dnssec_ok);
                                Ok(())
                            })
                            .unwrap();
                    }

                    let plain_rcode = if opcode == Opcode::QUERY {
                        OptRcode::FORMERR
                    } else {
                        OptRcode::NOTIMP
                    };
                    let tls_rcode = if opcode == Opcode::QUERY {
                        OptRcode::FORMERR
                    } else {
                        OptRcode::REFUSED
                    };

                    for (response, expected) in [
                        (
                            dns::exchange_request(request.clone(), key, |message| {
                                dns::exchange_udp(app.dns_port(), message)
                            }),
                            plain_rcode,
                        ),
                        (
                            dns::exchange_request(request.clone(), key, |message| {
                                dns::exchange_tcp(app.dns_port(), message)
                            }),
                            plain_rcode,
                        ),
                        (
                            dns::exchange_request(request, key, |message| {
                                dns::exchange_tls(
                                    app.dns_tls_port(),
                                    message,
                                    dns::dot_client(&app),
                                )
                            }),
                            tls_rcode,
                        ),
                    ] {
                        let response = response.unwrap();

                        assert_eq!(response.header().id(), 9619);
                        assert_eq!(response.header().opcode(), opcode);
                        assert!(response.header().qr() && response.header().rd());
                        assert!(!response.header().aa() && !response.header().tc());
                        assert_eq!(response.header_counts().qdcount(), 0);
                        assert_eq!(response.header_counts().ancount(), 0);
                        assert_eq!(response.header_counts().nscount(), 0);
                        assert_eq!(
                            response.opt_rcode(),
                            if version == Some(1) {
                                OptRcode::BADVERS
                            } else {
                                expected
                            }
                        );
                        assert_eq!(response.opt().is_some(), version.is_some());

                        if let Some(opt) = response.opt() {
                            assert_eq!(opt.version(), 0);
                            assert_eq!(opt.dnssec_ok(), dnssec_ok);
                        }

                        assert!(response.as_slice().len() <= 512);
                    }
                }
            }
        }
    }
}

/// Verify that an unsupported opcode needs only a header, not a QUERY-shaped body.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn unsupported_opcodes_return_refusals_without_questions() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;

    for edns in [false, true] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(8906);
        builder.header_mut().set_opcode(Opcode::from_int(15));
        let mut request = builder.additional();

        if edns {
            request
                .opt(|opt| {
                    opt.set_udp_payload_size(1232);
                    Ok(())
                })
                .unwrap();
        }

        let request = request.finish();

        for response in [
            dns::exchange_udp(app.dns_port(), &request).unwrap(),
            dns::exchange_tcp(app.dns_port(), &request).unwrap(),
        ] {
            let response = Message::from_octets(response).unwrap();

            assert_eq!(response.header().opcode(), Opcode::from_int(15));
            assert_eq!(response.header().rcode(), Rcode::NOTIMP);
            assert_eq!(response.header_counts().qdcount(), 0);
            assert_eq!(response.opt().is_some(), edns);
        }

        let response =
            dns::exchange_tls(app.dns_tls_port(), &request, dns::dot_client(&app)).unwrap();
        let response = Message::from_octets(response).unwrap();

        assert_eq!(response.header().rcode(), Rcode::REFUSED);
        assert_eq!(response.header_counts().qdcount(), 0);
        assert_eq!(response.opt().is_some(), edns);

        if let Some(opt) = response.opt() {
            assert_eq!(
                opt.opt()
                    .iter::<ExtendedError<_>>()
                    .next()
                    .unwrap()
                    .unwrap()
                    .code(),
                ExtendedErrorCode::NOT_SUPPORTED
            );
        }
    }
}

/// Verify that TSIG validation precedes question-count, EDNS-version, and opcode refusals.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn questionless_tsig_failures_keep_their_specific_errors() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let key = tsig::create_tsig_key(&app, "questionless-errors", KeyRole::Admin).await;

    for opcode in [Opcode::QUERY, Opcode::from_int(15)] {
        for version in [None, Some(0), Some(1)] {
            for (unknown, corrupt, age, mac_len, expected) in [
                (true, false, 0, 32, TsigRcode::BADKEY),
                (false, true, 0, 32, TsigRcode::BADSIG),
                (false, false, 3600, 32, TsigRcode::BADTIME),
                (false, false, 0, 16, TsigRcode::BADTRUNC),
                (false, true, 3600, 16, TsigRcode::BADSIG),
                (false, false, 3600, 16, TsigRcode::BADTIME),
            ] {
                let mut signing_key = key.clone();

                if unknown {
                    signing_key.name = "unregistered-questionless-key".to_string();
                }

                let mut builder = MessageBuilder::new_vec();
                builder.header_mut().set_id(8945);
                builder.header_mut().set_opcode(opcode);
                let mut request = builder.additional();

                if let Some(version) = version {
                    request
                        .opt(|opt| {
                            opt.set_udp_payload_size(512);
                            opt.set_version(version);
                            opt.set_dnssec_ok(true);
                            Ok(())
                        })
                        .unwrap();
                }

                let signed_at = Time48::from_u64(u64::from(Time48::now()) - age);
                ClientTransaction::request_with_fudge(
                    signing_key.to_tsig_key_with_mac_len(mac_len).unwrap(),
                    &mut request,
                    signed_at,
                    17,
                )
                .unwrap();
                let mut request = request.finish();

                if corrupt {
                    let mac_end = request.len() - 7;
                    request[mac_end] ^= 1;
                }

                for response in [
                    dns::exchange_udp(app.dns_port(), &request).unwrap(),
                    dns::exchange_tcp(app.dns_port(), &request).unwrap(),
                    dns::exchange_tls(app.dns_tls_port(), &request, dns::dot_client(&app)).unwrap(),
                ] {
                    let response = Message::from_octets(response).unwrap();

                    assert_eq!(response.header().id(), 8945);
                    assert_eq!(response.header().opcode(), opcode);
                    assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
                    assert_eq!(response.header_counts().qdcount(), 0);
                    assert_eq!(response.opt().is_some(), version.is_some());

                    if let Some(opt) = response.opt() {
                        assert_eq!(opt.version(), 0);
                        assert!(opt.dnssec_ok());
                    }

                    let tsig = response
                        .additional()
                        .unwrap()
                        .limit_to::<Tsig<_, _>>()
                        .last()
                        .unwrap()
                        .unwrap();

                    assert_eq!(tsig.data().error(), expected);
                    assert_eq!(
                        tsig.data().other().len(),
                        if expected == TsigRcode::BADTIME {
                            6
                        } else {
                            0
                        }
                    );

                    if expected == TsigRcode::BADKEY || expected == TsigRcode::BADSIG {
                        assert!(tsig.data().mac().is_empty());
                    } else {
                        assert_eq!(tsig.data().mac().len(), 32);
                        tsig::verify_response_mac(&request, &response, &key).unwrap();
                    }

                    assert!(response.as_slice().len() <= 512);
                }
            }
        }
    }
}

/// Verify that a nonstandard opcode body cannot be mistaken for a malformed QUERY or TSIG.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn unsupported_opcodes_return_refusals_for_opaque_bodies() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;

    for count in [0u16, 1, u16::MAX] {
        for body in [&[][..], &[0xc0, 0x0c][..], &[0xff; 32][..]] {
            let mut builder = MessageBuilder::new_vec();
            builder.header_mut().set_id(8906);
            builder.header_mut().set_opcode(Opcode::from_int(15));
            let mut request = builder.finish();
            request[4..6].copy_from_slice(&count.to_be_bytes());
            request.extend_from_slice(body);

            for response in [
                dns::exchange_udp(app.dns_port(), &request).unwrap(),
                dns::exchange_tcp(app.dns_port(), &request).unwrap(),
            ] {
                let response = Message::from_octets(response).unwrap();

                assert_eq!(response.header().rcode(), Rcode::NOTIMP);
                assert_eq!(response.header_counts().qdcount(), 0);
                assert_eq!(response.as_slice().len(), 12);
            }

            let response =
                dns::exchange_tls(app.dns_tls_port(), &request, dns::dot_client(&app)).unwrap();
            let response = Message::from_octets(response).unwrap();

            assert_eq!(response.header().rcode(), Rcode::REFUSED);
            assert_eq!(response.header_counts().qdcount(), 0);
            assert_eq!(response.as_slice().len(), 12);
        }
    }
}

/// Verify that invalid OPT/TSIG metadata remains FORMERR even when no question is present.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn questionless_malformed_extensions_receive_formerr() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let key = tsig::create_tsig_key(&app, "questionless-malformed", KeyRole::Admin).await;

    for malformed_tsig in [false, true] {
        let mut query = MessageBuilder::new_vec().additional();
        query
            .opt(|opt| {
                opt.set_udp_payload_size(512);
                Ok(())
            })
            .unwrap();

        if malformed_tsig {
            ClientTransaction::request(key.to_tsig_key().unwrap(), &mut query, Time48::now())
                .unwrap();
        } else {
            // A second OPT is invalid but its record boundaries are readable.
            query
                .opt(|opt| {
                    opt.set_udp_payload_size(512);
                    Ok(())
                })
                .unwrap();
        }

        let mut query = query.finish();

        if malformed_tsig {
            let message = Message::from_octets(query.as_slice()).unwrap();
            let mut additional = message.additional().unwrap();
            additional.next().unwrap().unwrap();
            let tsig_start = additional.pos();
            let owner_len = key.name.len() + 2;

            // TSIG requires CLASS ANY; zero breaks framing-independent validation.
            let class_start = tsig_start + owner_len + 2;
            query[class_start..class_start + 2].copy_from_slice(&0u16.to_be_bytes());
        }

        for response in [
            dns::exchange_udp(app.dns_port(), &query).unwrap(),
            dns::exchange_tcp(app.dns_port(), &query).unwrap(),
            dns::exchange_tls(app.dns_tls_port(), &query, dns::dot_client(&app)).unwrap(),
        ] {
            let response = Message::from_octets(response).unwrap();

            assert_eq!(response.header().rcode(), Rcode::FORMERR);
            assert_eq!(response.header_counts().qdcount(), 0);
            assert!(response.opt().is_some());
            assert!(
                !response
                    .additional()
                    .unwrap()
                    .any(|record| record.unwrap().rtype() == Rtype::TSIG)
            );
        }
    }
}

/// Verify that a refused message leaves both framed transports available for another
/// request.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn questionless_refusals_allow_connection_reuse() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let mut stream = dns::connect_tcp(app.dns_port()).unwrap();

    for opcode in [Opcode::QUERY, Opcode::from_int(15), Opcode::QUERY] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_opcode(opcode);
        dns::write_frame(&mut stream, &builder.finish()).unwrap();
        let response = dns::read_frame(&mut stream).unwrap().unwrap();
        let response = Message::from_octets(response).unwrap();

        assert_eq!(
            response.header().rcode(),
            if opcode == Opcode::QUERY {
                Rcode::FORMERR
            } else {
                Rcode::NOTIMP
            }
        );
    }

    let mut stream = dns::connect_tls(app.dns_tls_port(), dns::dot_client(&app)).unwrap();

    for opcode in [Opcode::QUERY, Opcode::from_int(15), Opcode::QUERY] {
        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_opcode(opcode);
        dns::write_frame(&mut stream, &builder.finish()).unwrap();
        let response = dns::read_frame(&mut stream).unwrap().unwrap();
        let response = Message::from_octets(response).unwrap();

        assert_eq!(
            response.header().rcode(),
            if opcode == Opcode::QUERY {
                Rcode::FORMERR
            } else {
                Rcode::REFUSED
            }
        );
    }
}
