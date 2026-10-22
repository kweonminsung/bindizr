//! IN-only query data, with EDNS and TSIG kept as protocol metadata.

use domain::{
    base::{
        Message, MessageBuilder, Ttl,
        iana::{Class, OptRcode, Rcode, Rtype, TsigRcode},
        message_builder::AdditionalBuilder,
    },
    rdata::{Soa, tsig::Tsig},
};
use serial_test::serial;

use super::tls::dot_client;
use crate::common::{
    TestApp, TestAppOptions,
    dns::{
        exchange_request, exchange_udp, parse_name,
        tsig::{KeyRole, create_tsig_key, sign},
    },
    exchange_tcp, exchange_xot,
};

/// An IN IXFR query cannot take its client serial from another class's SOA.
#[tokio::test]
#[serial]
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
    let key = create_tsig_key(&app, "ixfr-record-class", KeyRole::Admin).await;

    let name = parse_name(zone_name).unwrap();

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
        question.push((&name, Rtype::IXFR, Class::IN)).unwrap();
        let mut authority = question.authority();
        authority
            .push((
                &name,
                class,
                Ttl::ZERO,
                Soa::new(
                    name.clone(),
                    name.clone(),
                    serial.into(),
                    Ttl::ZERO,
                    Ttl::ZERO,
                    Ttl::ZERO,
                    Ttl::ZERO,
                ),
            ))
            .unwrap();
        let mut request = authority.additional();
        request
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
                exchange_request(request.clone(), key, |wire| {
                    exchange_udp(app.dns_port(), wire)
                }),
                exchange_request(request.clone(), key, |wire| {
                    exchange_tcp(app.dns_port(), wire)
                }),
                exchange_request(request.clone(), key, |wire| {
                    exchange_xot(app.dns_tls_port(), wire, dot_client(&app))
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
                    if class == Class::IN { 1 } else { 0 }
                );
                assert!(response.as_slice().len() <= 512);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional,
}

/// Include a foreign RR after a valid IN SOA where applicable.
fn build_query_with_foreign_record(
    section: Section,
    questions: usize,
    version: u8,
) -> AdditionalBuilder<Vec<u8>> {
    let name = parse_name("example.com").unwrap();
    let soa = Soa::new(
        name.clone(),
        name.clone(),
        1.into(),
        Ttl::ZERO,
        Ttl::ZERO,
        Ttl::ZERO,
        Ttl::ZERO,
    );
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(1035);
    let mut question = builder.question();

    for _ in 0..questions {
        question.push((&name, Rtype::SOA, Class::IN)).unwrap();
    }

    let mut answer = question.answer();

    if section == Section::Answer {
        answer.push((&name, Class::CH, Ttl::ZERO, &soa)).unwrap();
    }

    let mut authority = answer.authority();
    authority.push((&name, Class::IN, Ttl::ZERO, &soa)).unwrap();

    if section == Section::Authority {
        authority.push((&name, Class::CH, Ttl::ZERO, &soa)).unwrap();
    }

    let mut additional = authority.additional();

    if section == Section::Additional {
        additional
            .push((&name, Class::CH, Ttl::ZERO, &soa))
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

/// Every ordinary QUERY section is IN-only; count and EDNS errors keep their order.
#[tokio::test]
#[serial]
async fn queries_reject_foreign_classes_in_every_section() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let key = create_tsig_key(&app, "query-record-class", KeyRole::Admin).await;

    for section in [Section::Answer, Section::Authority, Section::Additional] {
        for questions in [1, 2] {
            for version in [0, 1] {
                let request = build_query_with_foreign_record(section, questions, version);

                for key in [None, Some(&key)] {
                    for response in [
                        exchange_request(request.clone(), key, |wire| {
                            exchange_udp(app.dns_port(), wire)
                        }),
                        exchange_request(request.clone(), key, |wire| {
                            exchange_tcp(app.dns_port(), wire)
                        }),
                        exchange_request(request.clone(), key, |wire| {
                            exchange_xot(app.dns_tls_port(), wire, dot_client(&app))
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

/// Class errors cannot bypass TSIG validation, including alongside BADVERS.
#[tokio::test]
#[serial]
async fn foreign_record_classes_keep_tsig_error_precedence() {
    let app = TestApp::start_with_options(TestAppOptions {
        dns_tls: true,
        ..Default::default()
    })
    .await;
    let key = create_tsig_key(&app, "bad-record-class", KeyRole::Admin).await;

    for unknown in [false, true] {
        let mut signing_key = key.clone();

        if unknown {
            signing_key.name = "unknown-record-class".to_string();
        }

        let mut request = build_query_with_foreign_record(Section::Authority, 1, 1);
        sign(&mut request, &signing_key).unwrap();
        let mut request = request.finish();

        if !unknown {
            let mac_end = request.len() - 7;
            request[mac_end] ^= 1;
        }

        for wire in [
            exchange_udp(app.dns_port(), &request),
            exchange_tcp(app.dns_port(), &request),
            exchange_xot(app.dns_tls_port(), &request, dot_client(&app)),
        ] {
            let response = Message::from_octets(wire.unwrap()).unwrap();

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
