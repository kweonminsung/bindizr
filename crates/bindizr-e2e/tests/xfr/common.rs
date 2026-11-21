//! Fixtures, clients and metrics shared by TCP and TLS transfer tests.

use std::time::{Duration, Instant};

use domain::base::MessageBuilder;
use domain::base::iana::{Class, Rtype};
use domain::base::message_builder::AdditionalBuilder;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use tokio::time;

use crate::common::{TestApp, dns};

/// Build a two-question QUERY with optional EDNS.
pub(crate) fn build_multi_question_query(
    zone_name: &str,
    qtype: Rtype,
    qclass: Class,
    opt_version: Option<u8>,
) -> AdditionalBuilder<Vec<u8>> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(9619);
    builder.header_mut().set_rd(true);
    let mut question = builder.question();
    question
        .push((&dns::parse_name(zone_name).unwrap(), qtype, qclass))
        .unwrap();
    question
        .push((
            &dns::parse_name("other.example").unwrap(),
            Rtype::A,
            Class::IN,
        ))
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
    zone_name: &str,
    qtype: Rtype,
    opts: &[(u8, bool)],
) -> AdditionalBuilder<Vec<u8>> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(3225);
    let mut question = builder.question();
    question
        .push((&dns::parse_name(zone_name).unwrap(), qtype))
        .unwrap();
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

/// Poll `/logs/transfer?{query}` until it selects `expected` rows, returning the last body on
/// timeout. Saving follows the transfer response, so an immediate read may not see the new row yet.
pub(crate) async fn wait_for_transfer_log(app: &TestApp, query: &str, expected: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        let (status, body) = app
            .send_request(Method::GET, &format!("/logs/transfer?{query}"), None)
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");

        if body["pagination"]["total"] == expected || Instant::now() > deadline {
            return body;
        }

        time::sleep(Duration::from_millis(50)).await;
    }
}
