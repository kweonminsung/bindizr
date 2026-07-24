use std::str::FromStr;

use domain::{
    base::{
        MessageBuilder, Name, Record, Ttl,
        iana::{Class, Rcode},
    },
    rdata::{A, Mx, Srv, Txt},
};
use serde_json::{Value, json};

use super::parse_dns_response;

#[test]
fn parse_dns_response_renders_values_in_harness_comparison_format() {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(7);
    builder.header_mut().set_qr(true);

    let owner = Name::<Vec<u8>>::from_str("www.example.com").unwrap();
    let target = Name::<Vec<u8>>::from_str("mail.example.com").unwrap();
    let ttl = Ttl::from_secs(300);

    let mut answer = builder.answer();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            ttl,
            A::from_octets(192, 0, 2, 1),
        ))
        .unwrap();
    answer
        .push(Record::new(&owner, Class::IN, ttl, Mx::new(5, &target)))
        .unwrap();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            ttl,
            Srv::new(1, 2, 8080, &target),
        ))
        .unwrap();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            ttl,
            Txt::<Vec<u8>>::build_from_slice(b"hello").unwrap(),
        ))
        .unwrap();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            ttl,
            Txt::from_octets(vec![2, b'a', b'b', 1, b'c']).unwrap(),
        ))
        .unwrap();

    let answers = parse_dns_response(7, &answer.finish()).unwrap();
    let values: Vec<(u16, Option<Value>)> = answers
        .into_iter()
        .map(|answer| (answer.record_type, answer.value))
        .collect();

    assert_eq!(
        values,
        vec![
            (1, Some(json!("192.0.2.1"))),
            (15, Some(json!("5 mail.example.com."))),
            (33, Some(json!("1 2 8080 mail.example.com."))),
            (16, Some(json!("hello"))),
            (16, Some(json!(["ab", "c"]))),
        ]
    );
}

// is_deleted_zone_absence matches on this exact "REFUSED RCODE" phrasing.
#[test]
fn parse_dns_response_names_refused_rcode_in_error() {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(9);
    builder.header_mut().set_qr(true);
    builder.header_mut().set_rcode(Rcode::REFUSED);

    let err = parse_dns_response(9, &builder.finish()).unwrap_err();
    assert!(err.contains("REFUSED RCODE (5)"), "unexpected error: {err}");
}

#[test]
fn parse_dns_response_treats_nxdomain_as_no_answers() {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(9);
    builder.header_mut().set_qr(true);
    builder.header_mut().set_rcode(Rcode::NXDOMAIN);

    let answers = parse_dns_response(9, &builder.finish()).unwrap();
    assert!(answers.is_empty());
}
