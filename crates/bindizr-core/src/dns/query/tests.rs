use std::str::FromStr;

use domain::{
    base::{
        Serial, Ttl,
        iana::{DigestAlgorithm, SecurityAlgorithm},
        opt::AllOptData,
    },
    rdata::A,
};

use super::*;

fn name(value: &str) -> Name<Vec<u8>> {
    Name::from_str(value).unwrap()
}

/// A response to a `qname`/`qtype` question with the flags and rcode given,
/// whose answer section holds `records` (owner, TTL, DS fields) and whose
/// authority section holds the SOA of `authority_soa`, if any.
fn build_ds_response(
    query_id: u16,
    qr: bool,
    aa: bool,
    tc: bool,
    rcode: Rcode,
    qname: &Name<Vec<u8>>,
    records: &[(&str, u32, u16)],
    authority_soa: Option<&str>,
) -> Vec<u8> {
    let mut builder = MessageBuilder::new_vec();
    let header = builder.header_mut();
    header.set_id(query_id);
    header.set_qr(qr);
    header.set_aa(aa);
    header.set_tc(tc);
    header.set_rcode(rcode);
    let mut question = builder.question();
    question.push((qname, Rtype::DS)).unwrap();
    let mut answer = question.answer();
    for (owner, ttl, key_tag) in records {
        answer
            .push((
                &name(owner),
                Class::IN,
                Ttl::from_secs(*ttl),
                Ds::new(
                    *key_tag,
                    SecurityAlgorithm::ECDSAP256SHA256,
                    DigestAlgorithm::SHA256,
                    vec![0xab; 32],
                )
                .unwrap(),
            ))
            .unwrap();
    }
    let mut authority = answer.authority();
    if let Some(owner) = authority_soa {
        authority
            .push((
                &name(owner),
                Class::IN,
                Ttl::from_secs(3600),
                Soa::new(
                    name("ns.parent.example"),
                    name("hostmaster.parent.example"),
                    Serial(1),
                    Ttl::from_secs(3600),
                    Ttl::from_secs(600),
                    Ttl::from_secs(86400),
                    Ttl::from_secs(300),
                ),
            ))
            .unwrap();
    }
    authority.finish()
}

/// The record `build_ds_response` serves for `key_tag`, as parsed.
fn parsed_ds_rr(key_tag: u16) -> DsRr {
    let mut rdata = key_tag.to_be_bytes().to_vec();
    rdata.extend_from_slice(&[13, 2]);
    rdata.extend_from_slice(&[0xab; 32]);
    DsRr { key_tag, rdata }
}

fn build_ns_response(
    query_id: u16,
    rcode: Rcode,
    qname: &Name<Vec<u8>>,
    names: &[&str],
) -> Vec<u8> {
    let mut builder = MessageBuilder::new_vec();
    let header = builder.header_mut();
    header.set_id(query_id);
    header.set_qr(true);
    header.set_rcode(rcode);
    let mut question = builder.question();
    question.push((qname, Rtype::NS)).unwrap();
    let mut answer = question.answer();
    for ns in names {
        answer
            .push((qname, Class::IN, Ttl::from_secs(3600), Ns::new(name(ns))))
            .unwrap();
    }
    answer.finish()
}

/// One AXFR response message with or without the echoed `question` and the
/// `aa` flag, answering one IN A record for `apex`.
fn build_transfer_message(id: u16, apex: &Name<Vec<u8>>, question: bool, aa: bool) -> Vec<u8> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(id);
    builder.header_mut().set_qr(true);
    builder.header_mut().set_aa(aa);
    let mut answer = if question {
        let mut q = builder.question();
        q.push((apex, Rtype::AXFR)).unwrap();
        q.answer()
    } else {
        builder.answer()
    };
    answer
        .push((
            apex,
            Class::IN,
            Ttl::from_secs(300),
            A::new("192.0.2.1".parse().unwrap()),
        ))
        .unwrap();
    answer.finish()
}

#[test]
fn transfer_rejects_a_non_in_rr() {
    let name: Name<Vec<u8>> = Name::from_str("example.com").unwrap();
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(7);
    builder.header_mut().set_qr(true);
    let mut answer = builder.answer();
    answer
        .push((
            &name,
            Class::CH,
            Ttl::from_secs(300),
            A::new("192.0.2.1".parse().unwrap()),
        ))
        .unwrap();
    let wire = answer.finish();

    let err = extract_transfer_rrs(7, &name, false, &wire).unwrap_err();
    assert!(err.contains("class"), "{err}");
}

#[test]
fn transfer_first_message_must_echo_the_question_and_be_authoritative() {
    let apex = name("example.com");
    let whole = build_transfer_message(7, &apex, true, true);
    assert_eq!(
        extract_transfer_rrs(7, &apex, true, &whole).unwrap().len(),
        1
    );

    let unasked = build_transfer_message(7, &apex, false, true);
    assert!(extract_transfer_rrs(7, &apex, true, &unasked).is_err());
    // A later message may leave the question out.
    assert_eq!(
        extract_transfer_rrs(7, &apex, false, &unasked)
            .unwrap()
            .len(),
        1
    );

    let cached = build_transfer_message(7, &apex, true, false);
    assert_eq!(
        extract_transfer_rrs(7, &apex, true, &cached).unwrap_err(),
        "response is not authoritative"
    );

    let other = build_transfer_message(7, &name("other.com"), true, true);
    assert_eq!(
        extract_transfer_rrs(7, &apex, false, &other).unwrap_err(),
        "response answers another question"
    );
}

#[test]
fn build_edns_question_advertises_the_payload_size() {
    let (query_id, wire) = build_edns_question(true, &name("example.com"), Rtype::DS);

    let message = Message::from_octets(wire.as_slice()).unwrap();
    assert_eq!(message.header().id(), query_id);
    assert!(message.header().rd());
    let question = message.sole_question().unwrap();
    assert_eq!(question.qtype(), Rtype::DS);
    let opt = message
        .opt()
        .expect("an OPT record in the additional section");
    assert_eq!(opt.udp_payload_size(), EDNS_UDP_PAYLOAD_SIZE);
    assert_eq!(opt.opt().iter::<AllOptData<_, _>>().count(), 0);
}

#[test]
fn extract_ds_rrset_reads_the_records_and_the_rrset_ttl() {
    let child = name("example.com");
    // The RRset TTL is the lowest member TTL (RFC 2181, Section 5.2), and
    // key tags come back ordered and without duplicates.
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[
            ("example.com", 86400, 34217),
            ("example.com", 3600, 2371),
            ("example.com", 86400, 34217),
        ],
        None,
    );

    assert_eq!(
        extract_ds_rrset(42, &child, &response).unwrap(),
        Some(DsRrset {
            records: vec![parsed_ds_rr(2371), parsed_ds_rr(34217)],
            ttl: 3600,
        })
    );
}

#[test]
fn extract_ds_rrset_reads_nodata_as_no_ds() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[],
        Some("com"),
    );
    assert_eq!(extract_ds_rrset(42, &child, &response).unwrap(), None);
}

#[test]
fn extract_ds_rrset_reads_nxdomain_as_no_ds() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NXDOMAIN,
        &child,
        &[],
        Some("com"),
    );
    assert_eq!(extract_ds_rrset(42, &child, &response).unwrap(), None);
}

#[test]
fn extract_ds_rrset_rejects_a_negative_answer_without_a_parent_soa() {
    let child = name("example.com");
    // The child's own server answers NODATA for its DS, with its own SOA.
    for authority_soa in [None, Some("example.com"), Some("other.com")] {
        let response = build_ds_response(
            42,
            true,
            true,
            false,
            Rcode::NOERROR,
            &child,
            &[],
            authority_soa,
        );
        assert_eq!(
            extract_ds_rrset(42, &child, &response).unwrap_err(),
            "negative answer carries no SOA of a parent zone",
            "{authority_soa:?}"
        );
    }
    let response = build_ds_response(42, true, true, false, Rcode::NXDOMAIN, &child, &[], None);
    assert!(extract_ds_rrset(42, &child, &response).is_err());
}

#[test]
fn extract_ds_rrset_rejects_an_answer_to_another_question() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &name("other.com"),
        &[],
        Some("com"),
    );
    assert_eq!(
        extract_ds_rrset(42, &child, &response).unwrap_err(),
        "response answers another question"
    );
}

#[test]
fn extract_ds_rrset_ignores_records_for_another_owner() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[("other.com", 3600, 1)],
        Some("com"),
    );
    assert_eq!(extract_ds_rrset(42, &child, &response).unwrap(), None);
}

#[test]
fn extract_ds_rrset_rejects_a_non_authoritative_answer() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        false,
        false,
        Rcode::NOERROR,
        &child,
        &[("example.com", 3600, 1)],
        None,
    );
    assert_eq!(
        extract_ds_rrset(42, &child, &response).unwrap_err(),
        "response is not authoritative"
    );
}

#[test]
fn extract_ds_rrset_rejects_a_truncated_answer() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        true,
        Rcode::NOERROR,
        &child,
        &[],
        Some("com"),
    );
    assert_eq!(
        extract_ds_rrset(42, &child, &response).unwrap_err(),
        "truncated response"
    );
}

#[test]
fn extract_ds_rrset_rejects_an_error_rcode() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::REFUSED,
        &child,
        &[],
        Some("com"),
    );
    assert_eq!(
        extract_ds_rrset(42, &child, &response).unwrap_err(),
        "RCODE 5"
    );
}

#[test]
fn extract_ds_rrset_rejects_id_mismatch() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[],
        Some("com"),
    );
    assert!(
        extract_ds_rrset(7, &child, &response)
            .unwrap_err()
            .contains("ID mismatch")
    );
}

#[test]
fn extract_ns_names_reads_the_answer_names() {
    let apex = name("com");
    let response = build_ns_response(
        9,
        Rcode::NOERROR,
        &apex,
        &["a.gtld-servers.net", "b.gtld-servers.net"],
    );
    assert_eq!(
        extract_ns_names(9, &apex, &response).unwrap(),
        vec!["a.gtld-servers.net.", "b.gtld-servers.net."]
    );
}

#[test]
fn extract_ns_names_reads_nxdomain_and_nodata_as_no_nameservers() {
    let apex = name("nx.example");
    let response = build_ns_response(9, Rcode::NXDOMAIN, &apex, &[]);
    assert!(extract_ns_names(9, &apex, &response).unwrap().is_empty());
    let response = build_ns_response(9, Rcode::NOERROR, &apex, &[]);
    assert!(extract_ns_names(9, &apex, &response).unwrap().is_empty());
}

#[test]
fn extract_ns_names_rejects_an_error_rcode() {
    let apex = name("com");
    let response = build_ns_response(9, Rcode::SERVFAIL, &apex, &[]);
    assert_eq!(
        extract_ns_names(9, &apex, &response).unwrap_err(),
        "RCODE 2"
    );
}

#[test]
fn is_truncated_reads_the_tc_flag() {
    let child = name("example.com");
    let truncated = build_ds_response(
        1,
        true,
        true,
        true,
        Rcode::NOERROR,
        &child,
        &[],
        Some("com"),
    );
    let whole = build_ds_response(
        1,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[],
        Some("com"),
    );
    assert!(is_truncated(&truncated));
    assert!(!is_truncated(&whole));
    assert!(!is_truncated(b"not a message"));
}
