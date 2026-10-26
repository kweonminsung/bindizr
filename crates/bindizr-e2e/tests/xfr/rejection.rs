//! Error responses to messages without a question, over every DNS transport.

use domain::base::iana::{Class, ExtendedErrorCode, Opcode, OptRcode, Rcode, Rtype, TsigRcode};
use domain::base::opt::exterr::ExtendedError;
use domain::base::{Message, MessageBuilder, Ttl};
use domain::rdata::tsig::{Time48, Tsig};
use domain::tsig::ClientTransaction;
use serial_test::serial;

use super::{common, tls};
use crate::common::dns::tsig;
use crate::common::dns::tsig::KeyRole;
use crate::common::{TestApp, TestAppOptions, dns};

/// TSIG error metrics follow the final RCODE, including overflow fallback.
#[tokio::test]
#[serial]
async fn tsig_error_metrics_follow_the_encoded_response() {
    let app = TestApp::start_local().await;

    let owner = crate::common::dns::parse_name(&format!(
        "{}.{}.{}.{}",
        "k".repeat(63),
        "l".repeat(63),
        "m".repeat(63),
        "n".repeat(61),
    ))
    .unwrap();
    let algorithm = crate::common::dns::parse_name(&format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
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
            let mut labels = vec![format!("result=\"{outcome}\"")];

            if metric == "bindizr_xfr_total" {
                labels.push(format!("type=\"{}\"", qtype.to_string().to_lowercase()));
                labels.push("transport=\"udp\"".to_string());
            }

            let labels: Vec<&str> = labels.iter().map(String::as_str).collect();

            let before = common::counter(&app, metric, &labels).await;

            let mut builder = MessageBuilder::new_vec();
            builder.header_mut().set_id(8945);
            builder.header_mut().set_opcode(opcode);
            let mut question = builder.question();
            question
                .push((
                    crate::common::dns::parse_name("example.com").unwrap(),
                    qtype,
                ))
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
            assert_eq!(common::counter(&app, metric, &labels).await, before + 1.0);
        }
    }
}

/// UPDATE parse failures retain SERVFAIL when TSIG error encoding fails.
#[tokio::test]
#[serial]
async fn questionless_updates_count_tsig_encoding_failure_as_servfail() {
    let app = TestApp::start_local().await;

    let owner = crate::common::dns::parse_name(&format!(
        "{}.{}.{}.{}",
        "k".repeat(63),
        "l".repeat(63),
        "m".repeat(63),
        "n".repeat(61),
    ))
    .unwrap();
    let algorithm = crate::common::dns::parse_name(&format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ))
    .unwrap();
    let labels = ["result=\"servfail\""];

    let before = common::counter(&app, "bindizr_nsupdate_requests_total", &labels).await;

    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(8945);
    builder.header_mut().set_opcode(Opcode::UPDATE);
    let mut request = builder.additional();
    request
        .opt(|opt| {
            opt.set_udp_payload_size(512);
            Ok(())
        })
        .unwrap();
    request
        .push((
            &owner,
            Class::ANY,
            Ttl::ZERO,
            Tsig::new(
                algorithm,
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

    assert_eq!(response.header().rcode(), Rcode::SERVFAIL);
    assert_eq!(response.header_counts().qdcount(), 0);
    assert!(response.as_slice().len() <= 512);
    assert_eq!(
        common::counter(&app, "bindizr_nsupdate_requests_total", &labels).await,
        before + 1.0,
    );
}

/// Signed UDP AXFR encoding failures count as failed transfers.
#[tokio::test]
#[serial]
async fn udp_axfr_counts_encoding_failure_before_truncation() {
    use std::io;
    use std::net::UdpSocket;
    use std::time::Duration;

    use reqwest::{Method, StatusCode};
    use serde_json::json;

    use crate::common::dns::tsig::SigningKey;

    let app = TestApp::start_local().await;

    let key_name = format!("{}.{}.{}.k", "d".repeat(63), "e".repeat(63), "f".repeat(63));

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({
                "name": key_name,
                "role_name": "admin",
                "algorithm": "hmac-sha512",
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    let key = SigningKey {
        name: key_name,
        secret: body["secret"].as_str().unwrap().to_string(),
        algorithm: domain::tsig::Algorithm::Sha512,
    };
    let qname = crate::common::dns::parse_name(&format!(
        "{}.{}.{}.q",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
    ))
    .unwrap();

    for advertised in [512, 1232] {
        let failed = ["type=\"axfr\"", "transport=\"udp\"", "result=\"failed\""];
        let truncated = ["type=\"axfr\"", "transport=\"udp\"", "result=\"truncated\""];

        let failed_before = common::counter(&app, "bindizr_xfr_total", &failed).await;
        let truncated_before = common::counter(&app, "bindizr_xfr_total", &truncated).await;

        let mut builder = MessageBuilder::new_vec();
        builder.header_mut().set_id(5936);
        let mut question = builder.question();
        question.push((&qname, Rtype::AXFR)).unwrap();
        let mut request = question.additional();
        request
            .opt(|opt| {
                opt.set_udp_payload_size(advertised);
                Ok(())
            })
            .unwrap();
        let client =
            ClientTransaction::request(key.to_tsig_key().unwrap(), &mut request, Time48::now())
                .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socket
            .send_to(&request.finish(), ("127.0.0.1", app.dns_port()))
            .unwrap();
        let mut response = vec![0; 4096];
        let received = socket.recv_from(&mut response);

        if advertised == 512 {
            assert!(matches!(
                received,
                Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock),
            ));
            assert_eq!(
                common::counter(&app, "bindizr_xfr_total", &failed).await,
                failed_before + 1.0
            );
            assert_eq!(
                common::counter(&app, "bindizr_xfr_total", &truncated).await,
                truncated_before
            );
        } else {
            response.truncate(received.unwrap().0);
            let mut response = Message::from_octets(response).unwrap();

            assert!(response.header().tc());
            assert_eq!(response.header().rcode(), Rcode::NOERROR);
            client.answer(&mut response, Time48::now()).unwrap();

            assert_eq!(
                common::counter(&app, "bindizr_xfr_total", &failed).await,
                failed_before
            );
            assert_eq!(
                common::counter(&app, "bindizr_xfr_total", &truncated).await,
                truncated_before + 1.0
            );
        }
    }
}

/// UPDATE validation failures still use readable EDNS when their TSIG error exceeds 512 bytes.
#[tokio::test]
#[serial]
async fn questionless_updates_use_readable_edns_for_tsig_errors() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;

    let owner = crate::common::dns::parse_name(&format!(
        "{}.{}.{}.{}",
        "k".repeat(63),
        "l".repeat(63),
        "m".repeat(63),
        "n".repeat(61),
    ))
    .unwrap();
    let algorithm = crate::common::dns::parse_name(&format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ))
    .unwrap();

    for opcode in [Opcode::QUERY, Opcode::UPDATE] {
        for advertised in [1232, 4096] {
            let mut builder = MessageBuilder::new_vec();
            builder.header_mut().set_id(8945);
            builder.header_mut().set_opcode(opcode);
            let mut request = builder.additional();
            request
                .opt(|opt| {
                    opt.set_udp_payload_size(advertised);
                    Ok(())
                })
                .unwrap();
            let tsig = Tsig::new(
                algorithm.clone(),
                Time48::now(),
                300,
                vec![0; 32],
                8945,
                TsigRcode::NOERROR,
                Vec::new(),
            )
            .unwrap();
            request.push((&owner, Class::ANY, Ttl::ZERO, tsig)).unwrap();
            let request = request.finish();

            for wire in [
                dns::exchange_udp(app.dns_port(), &request),
                crate::common::exchange_tcp(app.dns_port(), &request),
                crate::common::exchange_xot(app.dns_tls_port(), &request, tls::dot_client(&app)),
            ] {
                let response = Message::from_octets(wire.unwrap()).unwrap();

                assert!(response.as_slice().len() > 512);
                assert!(response.as_slice().len() <= 1232);
                assert_eq!(response.header().id(), 8945);
                assert_eq!(response.header().opcode(), opcode);
                assert_eq!(response.header().rcode(), Rcode::NOTAUTH);
                assert_eq!(response.header_counts().qdcount(), 0);
                assert_eq!(response.opt().unwrap().udp_payload_size(), 1232);
                let tsig = response
                    .additional()
                    .unwrap()
                    .limit_to::<Tsig<_, _>>()
                    .last()
                    .unwrap()
                    .unwrap();

                assert_eq!(tsig.data().error(), TsigRcode::BADKEY);
                assert!(tsig.data().mac().is_empty());
            }
        }
    }
}

/// A readable first question does not make a truncated later section usable.
#[tokio::test]
#[serial]
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
            .push((
                crate::common::dns::parse_name("example.com").unwrap(),
                domain::base::Rtype::SOA,
            ))
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
                crate::common::exchange_tcp(app.dns_port(), &request).unwrap(),
                crate::common::exchange_xot(app.dns_tls_port(), &request, tls::dot_client(&app))
                    .unwrap(),
            ] {
                let message = Message::from_octets(response.as_slice()).unwrap();

                assert_eq!(message.header().id(), 6891);
                assert_eq!(message.header().opcode(), opcode);
                assert!(message.header().qr() && message.header().rd());
                assert_eq!(message.header().rcode(), Rcode::FORMERR);
                assert_eq!(response.len(), 12);
                assert_eq!(message.header_counts().qdcount(), 0);
                assert_eq!(message.header_counts().arcount(), 0);
            }
        }
    }
}

/// Readable Additional sections remain meaningful when QDCOUNT is zero.
#[tokio::test]
#[serial]
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
                            dns::exchange_request(request.clone(), key, |wire| {
                                dns::exchange_udp(app.dns_port(), wire)
                            }),
                            plain_rcode,
                        ),
                        (
                            dns::exchange_request(request.clone(), key, |wire| {
                                crate::common::exchange_tcp(app.dns_port(), wire)
                            }),
                            plain_rcode,
                        ),
                        (
                            dns::exchange_request(request, key, |wire| {
                                crate::common::exchange_xot(
                                    app.dns_tls_port(),
                                    wire,
                                    tls::dot_client(&app),
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

/// An unsupported opcode needs only a header, not a QUERY-shaped body.
#[tokio::test]
#[serial]
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

        for wire in [
            dns::exchange_udp(app.dns_port(), &request),
            crate::common::exchange_tcp(app.dns_port(), &request),
        ] {
            let response = Message::from_octets(wire.unwrap()).unwrap();
            assert_eq!(response.header().opcode(), Opcode::from_int(15));
            assert_eq!(response.header().rcode(), Rcode::NOTIMP);
            assert_eq!(response.header_counts().qdcount(), 0);
            assert_eq!(response.opt().is_some(), edns);
        }

        let wire = crate::common::exchange_xot(app.dns_tls_port(), &request, tls::dot_client(&app))
            .unwrap();
        let response = Message::from_octets(wire).unwrap();

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

/// TSIG validation precedes question-count, EDNS-version, and opcode refusals.
#[tokio::test]
#[serial]
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

                for wire in [
                    dns::exchange_udp(app.dns_port(), &request),
                    crate::common::exchange_tcp(app.dns_port(), &request),
                    crate::common::exchange_xot(
                        app.dns_tls_port(),
                        &request,
                        tls::dot_client(&app),
                    ),
                ] {
                    let response = Message::from_octets(wire.unwrap()).unwrap();

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

/// A nonstandard opcode body cannot be mistaken for a malformed QUERY or TSIG.
#[tokio::test]
#[serial]
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

            for wire in [
                dns::exchange_udp(app.dns_port(), &request),
                crate::common::exchange_tcp(app.dns_port(), &request),
            ] {
                let response = Message::from_octets(wire.unwrap()).unwrap();
                assert_eq!(response.header().rcode(), Rcode::NOTIMP);
                assert_eq!(response.header_counts().qdcount(), 0);
                assert_eq!(response.as_slice().len(), 12);
            }

            let wire =
                crate::common::exchange_xot(app.dns_tls_port(), &request, tls::dot_client(&app))
                    .unwrap();
            let response = Message::from_octets(wire).unwrap();

            assert_eq!(response.header().rcode(), Rcode::REFUSED);
            assert_eq!(response.header_counts().qdcount(), 0);
            assert_eq!(response.as_slice().len(), 12);
        }
    }
}

/// Invalid OPT/TSIG metadata remains FORMERR even when no question is present.
#[tokio::test]
#[serial]
async fn questionless_malformed_extensions_receive_formerr() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let key = tsig::create_tsig_key(&app, "questionless-malformed", KeyRole::Admin).await;

    for malformed_tsig in [false, true] {
        let mut request = MessageBuilder::new_vec().additional();
        request
            .opt(|opt| {
                opt.set_udp_payload_size(512);
                Ok(())
            })
            .unwrap();

        if malformed_tsig {
            ClientTransaction::request(key.to_tsig_key().unwrap(), &mut request, Time48::now())
                .unwrap();
        } else {
            // A second OPT is invalid but its record boundaries are readable.
            request
                .opt(|opt| {
                    opt.set_udp_payload_size(512);
                    Ok(())
                })
                .unwrap();
        }

        let mut request = request.finish();

        if malformed_tsig {
            let message = Message::from_octets(request.as_slice()).unwrap();
            let mut additional = message.additional().unwrap();
            additional.next().unwrap().unwrap();
            let tsig_start = additional.pos();
            let owner_len = key.name.len() + 2;

            // TSIG requires CLASS ANY; zero breaks framing-independent validation.
            let class_start = tsig_start + owner_len + 2;
            request[class_start..class_start + 2].copy_from_slice(&0u16.to_be_bytes());
        }

        for wire in [
            dns::exchange_udp(app.dns_port(), &request),
            crate::common::exchange_tcp(app.dns_port(), &request),
            crate::common::exchange_xot(app.dns_tls_port(), &request, tls::dot_client(&app)),
        ] {
            let response = Message::from_octets(wire.unwrap()).unwrap();

            assert_eq!(response.header().rcode(), Rcode::FORMERR);
            assert_eq!(response.header_counts().qdcount(), 0);
            assert!(response.opt().is_some());
            assert!(
                !response
                    .additional()
                    .unwrap()
                    .any(|record| record.unwrap().rtype() == domain::base::Rtype::TSIG)
            );
        }
    }
}

/// A refused message leaves both framed transports available for another request.
#[tokio::test]
#[serial]
async fn questionless_refusals_allow_connection_reuse() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let mut tcp = dns::connect_tcp(app.dns_port()).unwrap();

    for opcode in [Opcode::QUERY, Opcode::from_int(15), Opcode::QUERY] {
        let mut request = MessageBuilder::new_vec();
        request.header_mut().set_opcode(opcode);
        dns::write_frame(&mut tcp, &request.finish()).unwrap();
        let response = Message::from_octets(dns::read_frame(&mut tcp).unwrap().unwrap()).unwrap();

        assert_eq!(
            response.header().rcode(),
            if opcode == Opcode::QUERY {
                Rcode::FORMERR
            } else {
                Rcode::NOTIMP
            }
        );
    }

    let mut tls = dns::connect_tls(app.dns_tls_port(), tls::dot_client(&app)).unwrap();

    for opcode in [Opcode::QUERY, Opcode::from_int(15), Opcode::QUERY] {
        let mut request = MessageBuilder::new_vec();
        request.header_mut().set_opcode(opcode);
        dns::write_frame(&mut tls, &request.finish()).unwrap();
        let response = Message::from_octets(dns::read_frame(&mut tls).unwrap().unwrap()).unwrap();

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
