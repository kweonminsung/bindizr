//! Catalog queries across equivalent presentations and generated-owner boundaries.

use domain::base::Message;
use domain::base::iana::{Rcode, Rtype};
use domain::rdata::Soa;

use super::common;
use crate::common::dns::tsig;
use crate::common::dns::tsig::KeyRole;
use crate::common::{TestApp, TestAppOptions, dns};

/// Resolve equivalent catalog names through SOA, AXFR and IXFR without changing the question.
#[tokio::test]
#[serial_test::serial]
async fn catalog_queries_match_equivalent_dns_escapes() {
    use domain::base::ToName;

    for (configured, question) in [
        (r"cat\046alog.example", r"CAT\.ALOG.EXAMPLE"),
        (r"cat\092alog.example", r"CAT\\ALOG.EXAMPLE"),
        (r"cat\255alog.example", r"CAT\255ALOG.EXAMPLE"),
        (r"cat\000alog.example", r"CAT\000ALOG.EXAMPLE"),
    ] {
        let app = TestApp::start_with_options(TestAppOptions {
            catalog_zone_name: configured.to_string(),
            ..Default::default()
        })
        .await;
        app.create_secondary("loopback", "127.0.0.1").await;
        app.create_test_zone().await;
        let signing_key = tsig::create_tsig_key(&app, "catalog-key", KeyRole::Admin).await;

        for key in [None, Some(&signing_key)] {
            for qtype in [Rtype::SOA, Rtype::IXFR] {
                let query = if qtype == Rtype::IXFR {
                    common::build_ixfr_query(question, 1)
                } else {
                    common::build_edns_query(question, qtype, &[(0, false)])
                };
                let response = dns::exchange_request(query, key, |bytes| {
                    dns::exchange_udp(app.dns_port(), bytes)
                })
                .unwrap();

                assert_eq!(
                    response.header().rcode(),
                    Rcode::NOERROR,
                    "{configured} {qtype}"
                );
                assert_eq!(
                    response
                        .sole_question()
                        .unwrap()
                        .qname()
                        .to_name::<Vec<u8>>()
                        .as_slice(),
                    dns::parse_name(question).unwrap().as_slice()
                );
                assert_eq!(response.header_counts().ancount(), 1);
                let query = if qtype == Rtype::IXFR {
                    common::build_ixfr_query(question, 1)
                } else {
                    common::build_edns_query(question, qtype, &[(0, false)])
                };
                let response = dns::exchange_request(query, key, |bytes| {
                    crate::common::exchange_tcp(app.dns_port(), bytes)
                })
                .unwrap();

                assert_eq!(
                    response.header().rcode(),
                    Rcode::NOERROR,
                    "{configured} {qtype}"
                );
                let echoed = response
                    .sole_question()
                    .unwrap()
                    .qname()
                    .to_name::<Vec<u8>>();

                assert_eq!(
                    echoed.as_slice(),
                    dns::parse_name(question).unwrap().as_slice()
                );
                assert!(response.header_counts().ancount() >= 1);
            }

            assert_eq!(
                crate::common::axfr(app.dns_port(), question, key)
                    .unwrap()
                    .records(),
                5
            );
        }
    }
}

/// Serve every generated catalog owner at the longest accepted catalog name.
#[tokio::test]
#[serial_test::serial]
async fn catalog_member_owners_fit_at_the_wire_length_boundary() {
    let catalog = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(22)
    );

    assert_eq!(dns::parse_name(&catalog).unwrap().as_slice().len(), 216);

    let app = TestApp::start_with_options(TestAppOptions {
        catalog_zone_name: catalog.clone(),
        ..Default::default()
    })
    .await;
    app.create_secondary("loopback", "127.0.0.1").await;

    assert_eq!(
        crate::common::axfr(app.dns_port(), &catalog, None)
            .unwrap()
            .records(),
        4
    );

    app.create_test_zone().await;

    assert_eq!(
        crate::common::axfr(app.dns_port(), &catalog, None)
            .unwrap()
            .records(),
        5
    );
    let query = common::build_edns_query(&catalog, Rtype::SOA, &[]).finish();
    let response =
        Message::from_octets(crate::common::exchange_tcp(app.dns_port(), &query).unwrap()).unwrap();

    assert_eq!(response.header().rcode(), Rcode::NOERROR);
    assert!(
        response
            .answer()
            .unwrap()
            .limit_to::<Soa<_>>()
            .next()
            .unwrap()
            .is_ok()
    );
}
