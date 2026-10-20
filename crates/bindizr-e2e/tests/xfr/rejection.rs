//! Error responses to messages without a question, over every DNS transport.

use domain::{
    base::{
        Message, MessageBuilder,
        iana::{ExtendedErrorCode, Opcode, OptRcode, Rcode, TsigRcode},
        opt::exterr::ExtendedError,
    },
    rdata::tsig::{Time48, Tsig},
    tsig::ClientTransaction,
};
use serial_test::serial;

use super::tls::dot_client;
use crate::common::{
    TestApp, TestAppOptions,
    dns::{
        connect_tcp, connect_tls, exchange_request, exchange_udp, read_frame,
        tsig::{KeyRole, create_tsig_key, verify_response_mac},
        write_frame,
    },
    exchange_tcp, exchange_xot,
};

/// Readable Additional sections remain meaningful when QDCOUNT is zero.
#[tokio::test]
#[serial]
async fn questionless_queries_preserve_edns_and_tsig() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let key = create_tsig_key(&app, "questionless-key", KeyRole::Admin).await;
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
                            exchange_request(request.clone(), key, |wire| {
                                exchange_udp(app.dns_port(), wire)
                            }),
                            plain_rcode,
                        ),
                        (
                            exchange_request(request.clone(), key, |wire| {
                                exchange_tcp(app.dns_port(), wire)
                            }),
                            plain_rcode,
                        ),
                        (
                            exchange_request(request, key, |wire| {
                                exchange_xot(app.dns_tls_port(), wire, dot_client(&app))
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
            exchange_udp(app.dns_port(), &request),
            exchange_tcp(app.dns_port(), &request),
        ] {
            let response = Message::from_octets(wire.unwrap()).unwrap();
            assert_eq!(response.header().opcode(), Opcode::from_int(15));
            assert_eq!(response.header().rcode(), Rcode::NOTIMP);
            assert_eq!(response.header_counts().qdcount(), 0);
            assert_eq!(response.opt().is_some(), edns);
        }
        let wire = exchange_xot(app.dns_tls_port(), &request, dot_client(&app)).unwrap();
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
    let key = create_tsig_key(&app, "questionless-errors", KeyRole::Admin).await;
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
                    exchange_udp(app.dns_port(), &request),
                    exchange_tcp(app.dns_port(), &request),
                    exchange_xot(app.dns_tls_port(), &request, dot_client(&app)),
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
                        if expected == TsigRcode::BADTIME { 6 } else { 0 }
                    );
                    if expected == TsigRcode::BADKEY || expected == TsigRcode::BADSIG {
                        assert!(tsig.data().mac().is_empty());
                    } else {
                        assert_eq!(tsig.data().mac().len(), 32);
                        verify_response_mac(&request, &response, &key).unwrap();
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
                exchange_udp(app.dns_port(), &request),
                exchange_tcp(app.dns_port(), &request),
            ] {
                let response = Message::from_octets(wire.unwrap()).unwrap();
                assert_eq!(response.header().rcode(), Rcode::NOTIMP);
                assert_eq!(response.header_counts().qdcount(), 0);
                assert_eq!(response.as_slice().len(), 12);
            }
            let wire = exchange_xot(app.dns_tls_port(), &request, dot_client(&app)).unwrap();
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
    let key = create_tsig_key(&app, "questionless-malformed", KeyRole::Admin).await;
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
            exchange_udp(app.dns_port(), &request),
            exchange_tcp(app.dns_port(), &request),
            exchange_xot(app.dns_tls_port(), &request, dot_client(&app)),
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
    let mut tcp = connect_tcp(app.dns_port()).unwrap();
    for opcode in [Opcode::QUERY, Opcode::from_int(15), Opcode::QUERY] {
        let mut request = MessageBuilder::new_vec();
        request.header_mut().set_opcode(opcode);
        write_frame(&mut tcp, &request.finish()).unwrap();
        let response = Message::from_octets(read_frame(&mut tcp).unwrap().unwrap()).unwrap();
        assert_eq!(
            response.header().rcode(),
            if opcode == Opcode::QUERY {
                Rcode::FORMERR
            } else {
                Rcode::NOTIMP
            }
        );
    }
    let mut tls = connect_tls(app.dns_tls_port(), dot_client(&app)).unwrap();
    for opcode in [Opcode::QUERY, Opcode::from_int(15), Opcode::QUERY] {
        let mut request = MessageBuilder::new_vec();
        request.header_mut().set_opcode(opcode);
        write_frame(&mut tls, &request.finish()).unwrap();
        let response = Message::from_octets(read_frame(&mut tls).unwrap().unwrap()).unwrap();
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
