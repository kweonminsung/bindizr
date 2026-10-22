//! Fixtures and metrics shared by TCP and TLS transfer tests.

use domain::{
    base::{
        MessageBuilder, Ttl,
        iana::{Class, Rtype},
        message_builder::AdditionalBuilder,
    },
    rdata::Soa,
};
use reqwest::{Method, StatusCode};

use crate::common::{TestApp, dns::parse_name};

/// Read one series of a counter from `/metrics`, picked by its labels.
pub(crate) async fn counter(app: &TestApp, name: &str, labels: &[&str]) -> f64 {
    let (status, body) = app.send_request(Method::GET, "/metrics", None).await;

    assert_eq!(status, StatusCode::OK);
    let text = body.as_str().expect("metrics body is prometheus text");

    text.lines()
        .filter(|line| line.starts_with(&format!("{name}{{")))
        .find(|line| labels.iter().all(|label| line.contains(label)))
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .unwrap_or_else(|| panic!("{name} {labels:?} missing from the scrape"))
}

/// Build an IXFR query carrying the client's SOA serial.
pub(crate) fn build_ixfr_query(zone: &str, serial: u32) -> AdditionalBuilder<Vec<u8>> {
    let name = parse_name(zone).unwrap();
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(1995);
    let mut question = builder.question();
    question.push((&name, Rtype::IXFR, Class::IN)).unwrap();
    let mut authority = question.authority();

    // RFC 1995, Section 3: the client's SOA belongs in the authority section.
    authority
        .push((
            &name,
            Class::IN,
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

    authority.additional()
}

/// Build a two-question QUERY with optional EDNS.
pub(crate) fn build_multi_question_query(
    zone: &str,
    qtype: Rtype,
    qclass: Class,
    opt_version: Option<u8>,
) -> AdditionalBuilder<Vec<u8>> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(9619);
    builder.header_mut().set_rd(true);
    let mut question = builder.question();
    question
        .push((&parse_name(zone).unwrap(), qtype, qclass))
        .unwrap();
    question
        .push((&parse_name("other.example").unwrap(), Rtype::A, Class::IN))
        .unwrap();
    let mut additional = question.additional();

    if let Some(version) = opt_version {
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(4096);
                opt.set_version(version);
                opt.set_dnssec_ok(true);
                Ok(())
            })
            .unwrap();
    }

    additional
}

/// Build a query with the specified OPT versions and DO bits.
pub(crate) fn build_edns_query(
    zone: &str,
    qtype: Rtype,
    opts: &[(u8, bool)],
) -> AdditionalBuilder<Vec<u8>> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(3225);
    let mut question = builder.question();
    question.push((&parse_name(zone).unwrap(), qtype)).unwrap();
    let mut additional = question.additional();

    for (version, dnssec_ok) in opts {
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(4096);
                opt.set_version(*version);
                opt.set_dnssec_ok(*dnssec_ok);
                Ok(())
            })
            .unwrap();
    }

    additional
}
