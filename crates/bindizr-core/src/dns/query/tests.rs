use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use domain::base::iana::{
    Class, DigestAlgorithm, Opcode, OptRcode, Rcode, Rtype, SecurityAlgorithm,
};
use domain::base::opt::AllOptData;
use domain::base::{Message, MessageBuilder, Name};
use domain::rdata::{A, Ds, Soa};

use super::*;
use crate::dns::dnssec::KeyTag;
use crate::dns::message::EDNS_UDP_PAYLOAD_SIZE;

/// Parse a DNS wire-format name for the test.
fn name(value: &str) -> Name<Vec<u8>> {
    Name::from_str(value).unwrap()
}

/// Verify that keepalive responses carry one two-octet timeout and zero is a valid close request.
#[test]
fn extract_tcp_keepalive_checks_timeout_units_and_option_shape() {
    for (data, expected) in [
        (vec![0, 11, 0, 2, 0, 0], Some(Duration::ZERO)),
        (vec![0, 11, 0, 2, 0, 1], Some(Duration::from_millis(100))),
        (
            vec![0, 11, 0, 2, 255, 255],
            Some(Duration::from_millis(6_553_500)),
        ),
        (Vec::new(), None),
    ] {
        let mut response = build_soa_response(1, &name("example.com"), Class::IN);

        assert_eq!(extract_tcp_keepalive_timeout(&response).unwrap(), None);
        append_opt(&mut response, OptRcode::NOERROR, 0);
        let end = response.len();
        response[end - 2..].copy_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);

        assert_eq!(extract_tcp_keepalive_timeout(&response).unwrap(), expected);
    }

    for data in [
        vec![0, 11, 0, 0],
        vec![0, 11, 0, 1, 0],
        vec![0, 11, 0, 3, 0, 0, 0],
        vec![0, 11, 0, 2, 0, 0, 0, 11, 0, 2, 0, 1],
    ] {
        let mut response = build_soa_response(1, &name("example.com"), Class::IN);
        append_opt(&mut response, OptRcode::NOERROR, 0);
        let end = response.len();
        response[end - 2..].copy_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);

        assert!(matches!(
            extract_tcp_keepalive_timeout(&response),
            Err(ParseResponseError::MalformedEdns)
        ));
    }
}

/// Build a DNS response with DS answers and an optional authority SOA.
fn build_ds_response(
    query_id: u16,
    qr: bool,
    aa: bool,
    tc: bool,
    rcode: Rcode,
    qname: &Name<Vec<u8>>,
    records: &[(&str, Class, u32, u16)],
    authority_soa: Option<(&str, Class)>,
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

    for (owner, class, ttl, key_tag) in records {
        answer
            .push((
                &name(owner),
                *class,
                domain::base::Ttl::from_secs(*ttl),
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

    if let Some((owner, class)) = authority_soa {
        authority
            .push((
                &name(owner),
                class,
                domain::base::Ttl::from_secs(3600),
                Soa::new(
                    name("ns.parent.example"),
                    name("hostmaster.parent.example"),
                    domain::base::Serial(1),
                    domain::base::Ttl::from_secs(3600),
                    domain::base::Ttl::from_secs(600),
                    domain::base::Ttl::from_secs(86400),
                    domain::base::Ttl::from_secs(300),
                ),
            ))
            .unwrap();
    }

    authority.finish()
}

/// Append OPT response metadata with explicit RCODE and VERSION.
fn append_opt(response: &mut Vec<u8>, rcode: OptRcode, version: u8) {
    let count = u16::from_be_bytes([response[10], response[11]]) + 1;
    response[10..12].copy_from_slice(&count.to_be_bytes());
    response[3] = (response[3] & 0xf0) | (rcode.to_int() as u8 & 0x0f);
    response.extend_from_slice(&[0, 0, 41, 4, 208]);
    let flags = (u32::from(rcode.to_int() >> 4) << 24) | (u32::from(version) << 16);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
}

/// Build an authoritative SOA answer with an explicit record class.
fn build_soa_response(query_id: u16, qname: &Name<Vec<u8>>, class: Class) -> Vec<u8> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(query_id);
    builder.header_mut().set_qr(true);
    builder.header_mut().set_aa(true);
    let mut question = builder.question();
    question.push((qname, Rtype::SOA)).unwrap();
    let mut answer = question.answer();
    answer
        .push((
            qname,
            class,
            domain::base::Ttl::from_secs(300),
            Soa::new(
                name("ns.example.com"),
                name("admin.example.com"),
                domain::base::Serial(2026),
                domain::base::Ttl::from_secs(300),
                domain::base::Ttl::from_secs(60),
                domain::base::Ttl::from_secs(86400),
                domain::base::Ttl::from_secs(300),
            ),
        ))
        .unwrap();

    answer.finish()
}

/// Build the record `build_ds_response` serves for `key_tag`, as parsed.
fn parsed_ds_record(key_tag: u16) -> DsRecord {
    let mut rdata = key_tag.to_be_bytes().to_vec();
    rdata.extend_from_slice(&[13, 2]);
    rdata.extend_from_slice(&[0xab; 32]);

    DsRecord {
        key_tag: KeyTag::from(key_tag),
        digest_type: 2,
        rdata,
    }
}

/// Build an IN A transfer response with configurable question and AA flag.
fn build_transfer_message(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    question: bool,
    aa: bool,
) -> Vec<u8> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(query_id);
    builder.header_mut().set_qr(true);
    builder.header_mut().set_aa(aa);
    let mut answer = if question {
        let mut question = builder.question();
        question.push((qname, Rtype::AXFR)).unwrap();
        question.answer()
    } else {
        builder.answer()
    };
    answer
        .push((
            qname,
            Class::IN,
            domain::base::Ttl::from_secs(300),
            A::new("192.0.2.1".parse::<Ipv4Addr>().unwrap()),
        ))
        .unwrap();

    answer.finish()
}

/// Verify that a transfer rejects a record of a class other than IN.
#[test]
fn transfer_rejects_a_non_in_record() {
    let name = name("example.com");
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(7);
    builder.header_mut().set_qr(true);
    let mut answer = builder.answer();
    answer
        .push((
            &name,
            Class::CH,
            domain::base::Ttl::from_secs(300),
            A::new("192.0.2.1".parse::<Ipv4Addr>().unwrap()),
        ))
        .unwrap();
    let wire = answer.finish();

    let result = extract_transfer_records(7, &name, TransferMessagePosition::Following, &wire);

    assert!(
        matches!(result, Err(ParseResponseError::ForeignClass { .. })),
        "{result:?}"
    );
}

/// Verify that AXFR requires its question but ignores AA and TC without relaxing ordinary queries.
#[test]
fn transfer_requires_question_and_ignores_aa_and_tc() {
    let apex = name("example.com");
    let whole = build_transfer_message(7, &apex, true, true);

    assert_eq!(
        extract_transfer_records(7, &apex, TransferMessagePosition::First, &whole)
            .unwrap()
            .len(),
        1
    );

    let unasked = build_transfer_message(7, &apex, false, true);

    assert!(extract_transfer_records(7, &apex, TransferMessagePosition::First, &unasked).is_err());

    // A later message may leave the question out.
    assert_eq!(
        extract_transfer_records(7, &apex, TransferMessagePosition::Following, &unasked)
            .unwrap()
            .len(),
        1
    );

    for aa in [false, true] {
        let mut response = build_transfer_message(7, &apex, true, aa);
        response[2] |= 0x02; // TC is ignored by AXFR clients (RFC 5936, Section 2).

        assert_eq!(
            extract_transfer_records(7, &apex, TransferMessagePosition::First, &response)
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            extract_soa_serial(7, &apex, &response),
            Err(ParseResponseError::Truncated)
        ));
    }

    let other = build_transfer_message(7, &name("other.com"), true, true);

    assert!(matches!(
        extract_transfer_records(7, &apex, TransferMessagePosition::Following, &other),
        Err(ParseResponseError::OtherQuestion)
    ));
}

/// Verify that a question advertises the requested EDNS payload size.
#[test]
fn build_question_advertises_edns_payload_size() {
    let (query_id, additional) = build_question(
        Opcode::QUERY,
        false,
        true,
        &name("example.com"),
        Rtype::DS,
        Some(EDNS_UDP_PAYLOAD_SIZE),
    );
    let wire = additional.finish();

    let message = Message::from_octets(wire.as_slice()).unwrap();

    assert_eq!(message.header().id(), query_id);
    assert!(message.header().rd());
    let question = message.sole_question().unwrap();

    assert_eq!(question.qtype(), Rtype::DS);
    let opt = message.opt().unwrap();

    assert_eq!(opt.udp_payload_size(), EDNS_UDP_PAYLOAD_SIZE);
    assert_eq!(opt.opt().iter::<AllOptData<_, _>>().count(), 0);
}

/// Verify that DS parsing normalizes record order, duplicates, and TTL.
#[test]
fn extract_ds_record_set_reads_the_records_and_the_record_set_ttl() {
    let child = name("example.com");

    // RFC 2181, Section 5.2: use the lowest member TTL.
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[
            ("example.com", Class::IN, 86400, 34217),
            ("example.com", Class::IN, 3600, 2371),
            ("example.com", Class::IN, 86400, 34217),
        ],
        None,
    );

    assert_eq!(
        extract_ds_record_set(42, &child, &response).unwrap(),
        Some(DsRecordSet {
            records: vec![parsed_ds_record(2371), parsed_ds_record(34217)],
            ttl: 3600,
        })
    );
}

/// Verify that `extract_ds_record_set` reads nodata as no DS.
#[test]
fn extract_ds_record_set_reads_nodata_as_no_ds() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[],
        Some(("com", Class::IN)),
    );

    assert_eq!(extract_ds_record_set(42, &child, &response).unwrap(), None);
}

/// Verify that `extract_ds_record_set` reads nxdomain as no DS.
#[test]
fn extract_ds_record_set_reads_nxdomain_as_no_ds() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NXDOMAIN,
        &child,
        &[],
        Some(("com", Class::IN)),
    );

    assert_eq!(extract_ds_record_set(42, &child, &response).unwrap(), None);
}

/// Verify that `extract_ds_record_set` rejects a negative answer without a parent SOA.
#[test]
fn extract_ds_record_set_rejects_a_negative_answer_without_a_parent_soa() {
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
            authority_soa.map(|owner| (owner, Class::IN)),
        );

        assert!(
            matches!(
                extract_ds_record_set(42, &child, &response),
                Err(ParseResponseError::NoParentSoa)
            ),
            "{authority_soa:?}"
        );
    }

    let response = build_ds_response(42, true, true, false, Rcode::NXDOMAIN, &child, &[], None);

    assert!(extract_ds_record_set(42, &child, &response).is_err());
}

/// Verify that `extract_ds_record_set` rejects an answer to another question.
#[test]
fn extract_ds_record_set_rejects_an_answer_to_another_question() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &name("other.com"),
        &[],
        Some(("com", Class::IN)),
    );

    assert!(matches!(
        extract_ds_record_set(42, &child, &response),
        Err(ParseResponseError::OtherQuestion)
    ));
}

/// Verify that `extract_ds_record_set` ignores records for another owner.
#[test]
fn extract_ds_record_set_ignores_records_for_another_owner() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[("other.com", Class::IN, 3600, 1)],
        Some(("com", Class::IN)),
    );

    assert_eq!(extract_ds_record_set(42, &child, &response).unwrap(), None);
}

/// Verify that `extract_ds_record_set` rejects a non authoritative answer.
#[test]
fn extract_ds_record_set_rejects_a_non_authoritative_answer() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        false,
        false,
        Rcode::NOERROR,
        &child,
        &[("example.com", Class::IN, 3600, 1)],
        None,
    );

    assert!(matches!(
        extract_ds_record_set(42, &child, &response),
        Err(ParseResponseError::NotAuthoritative)
    ));
}

/// Verify that `extract_ds_record_set` rejects a truncated answer.
#[test]
fn extract_ds_record_set_rejects_a_truncated_answer() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        true,
        Rcode::NOERROR,
        &child,
        &[],
        Some(("com", Class::IN)),
    );

    assert!(matches!(
        extract_ds_record_set(42, &child, &response),
        Err(ParseResponseError::Truncated)
    ));
}

/// Verify that `extract_ds_record_set` rejects an error rcode.
#[test]
fn extract_ds_record_set_rejects_an_error_rcode() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::REFUSED,
        &child,
        &[],
        Some(("com", Class::IN)),
    );

    assert!(matches!(
        extract_ds_record_set(42, &child, &response),
        Err(ParseResponseError::Rcode {
            rcode: OptRcode::REFUSED
        })
    ));
}

/// Verify that `extract_ds_record_set` rejects id mismatch.
#[test]
fn extract_ds_record_set_rejects_id_mismatch() {
    let child = name("example.com");
    let response = build_ds_response(
        42,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[],
        Some(("com", Class::IN)),
    );

    assert!(matches!(
        extract_ds_record_set(7, &child, &response),
        Err(ParseResponseError::IdMismatch { .. })
    ));
}

/// Verify that extended errors cannot become successful DS, SOA, AXFR, or NOTIFY responses.
#[test]
fn responses_reject_extended_rcodes() {
    let child = name("example.com");

    for code in [16, 20, 4095] {
        let rcode = OptRcode::masked_from_int(code);
        let mut ds = build_ds_response(
            42,
            true,
            true,
            false,
            Rcode::NOERROR,
            &child,
            &[],
            Some(("com", Class::IN)),
        );
        append_opt(&mut ds, rcode, 0);

        assert!(
            matches!(extract_ds_record_set(42, &child, &ds), Err(ParseResponseError::Rcode { rcode: got }) if got == rcode),
            "DS did not preserve {code}"
        );

        let mut soa = build_soa_response(42, &child, Class::IN);
        append_opt(&mut soa, rcode, 0);

        assert!(
            matches!(extract_soa_serial(42, &child, &soa), Err(ParseResponseError::Rcode { rcode: got }) if got == rcode),
            "SOA did not preserve {code}"
        );

        let mut transfer = build_transfer_message(42, &child, true, true);
        append_opt(&mut transfer, rcode, 0);

        assert!(
            matches!(extract_transfer_records(42, &child, TransferMessagePosition::First, &transfer), Err(ParseResponseError::Rcode { rcode: got }) if got == rcode),
            "AXFR did not preserve {code}"
        );

        let (query_id, additional) =
            build_question(Opcode::NOTIFY, true, false, &child, Rtype::SOA, None);
        let mut notify = additional.finish();
        notify[2] |= 0x80;
        append_opt(&mut notify, rcode, 0);
        assert!(
            matches!(validate_notify_response(query_id, &child, &notify), Err(ParseResponseError::Rcode { rcode: got }) if got == rcode),
            "NOTIFY did not preserve {code}"
        );
    }
}

/// Verify that responses may advertise a newer EDNS version.
#[test]
fn responses_accept_advertised_edns_versions() {
    let child = name("example.com");
    for version in [0, 1, 255] {
        let mut response = build_soa_response(42, &child, Class::IN);
        append_opt(&mut response, OptRcode::NOERROR, version);
        assert_eq!(extract_soa_serial(42, &child, &response).unwrap(), 2026);
    }
}

/// Verify that malformed OPT cannot justify an answer or TCP retry.
#[test]
fn responses_reject_malformed_opt_records() {
    let child = name("example.com");
    let (query_id, additional) =
        build_question(Opcode::QUERY, false, false, &child, Rtype::DS, Some(1232));
    let request = additional.finish();
    let mut response = build_ds_response(
        query_id,
        true,
        true,
        false,
        Rcode::NOERROR,
        &child,
        &[],
        Some(("com", Class::IN)),
    );
    append_opt(&mut response, OptRcode::NOERROR, 0);
    let mut duplicate = response.clone();
    append_opt(&mut duplicate, OptRcode::NOERROR, 0);
    let mut nonroot = response.clone();
    let opt_start = nonroot.len() - 11;
    nonroot.splice(opt_start..opt_start, [1, b'x']);
    let mut short_option = response;
    let rdlen = short_option.len() - 2;
    short_option[rdlen..].copy_from_slice(&3u16.to_be_bytes());
    short_option.extend_from_slice(&[0, 15, 0]);

    let mut misplaced = Vec::new();

    for count_offset in [6, 8] {
        let mut wire = build_ds_response(
            query_id,
            true,
            true,
            false,
            Rcode::NOERROR,
            &child,
            &[],
            None,
        );
        append_opt(&mut wire, OptRcode::NOERROR, 0);
        wire[10..12].copy_from_slice(&0u16.to_be_bytes());
        wire[count_offset..count_offset + 2].copy_from_slice(&1u16.to_be_bytes());
        misplaced.push(wire);
    }

    for mut wire in [duplicate, nonroot, short_option]
        .into_iter()
        .chain(misplaced)
    {
        assert!(matches!(
            extract_ds_record_set(query_id, &child, &wire),
            Err(ParseResponseError::MalformedEdns)
        ));
        assert!(!matches_response_to_request(&request, &wire));
        wire[2] |= 0x02;

        assert!(!matches_response_to_request(&request, &wire));
    }
}

/// Verify that foreign-class DS is rejected even beside an IN parent SOA.
#[test]
fn extract_ds_record_set_rejects_foreign_classes() {
    let child = name("example.com");

    for class in [Class::CH, Class::HS] {
        let response = build_ds_response(
            42,
            true,
            true,
            false,
            Rcode::NOERROR,
            &child,
            &[("example.com", class, 300, 1)],
            Some(("com", Class::IN)),
        );

        assert!(
            extract_ds_record_set(42, &child, &response).is_err(),
            "accepted {class}"
        );
    }
}

/// Verify that foreign-class SOA cannot prove IN DS absence.
#[test]
fn extract_ds_record_set_rejects_foreign_parent_soa_classes() {
    let child = name("example.com");

    for rcode in [Rcode::NOERROR, Rcode::NXDOMAIN] {
        let response = build_ds_response(
            42,
            true,
            true,
            false,
            rcode,
            &child,
            &[],
            Some(("com", Class::CH)),
        );

        assert!(
            extract_ds_record_set(42, &child, &response).is_err(),
            "accepted {rcode}"
        );
    }
}

/// Verify that SOA polling uses only the queried class's serial.
#[test]
fn extract_soa_serial_rejects_foreign_classes() {
    let apex = name("example.com");

    for class in [Class::CH, Class::HS] {
        let response = build_soa_response(42, &apex, class);
        assert!(
            extract_soa_serial(42, &apex, &response).is_err(),
            "accepted {class}"
        );
    }
}

/// Build an SOA response with raw header `flags`, its question for `qname`,
/// and, when `with_answer`, one SOA answer carrying `serial`.
fn build_flagged_soa_response(
    query_id: u16,
    flags: u16,
    qname: &str,
    with_answer: bool,
    serial: u32,
) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&query_id.to_be_bytes());
    buffer.extend_from_slice(&flags.to_be_bytes());
    buffer.extend_from_slice(&1u16.to_be_bytes());
    buffer.extend_from_slice(&u16::from(with_answer).to_be_bytes());
    buffer.extend_from_slice(&0u16.to_be_bytes());
    buffer.extend_from_slice(&0u16.to_be_bytes());

    buffer.extend_from_slice(&crate::dns::name::encode_name(qname).unwrap());
    buffer.extend_from_slice(&Rtype::SOA.to_int().to_be_bytes());
    buffer.extend_from_slice(&Class::IN.to_int().to_be_bytes());

    if with_answer {
        buffer.extend_from_slice(&crate::dns::name::encode_name(qname).unwrap());
        buffer.extend_from_slice(&Rtype::SOA.to_int().to_be_bytes());
        buffer.extend_from_slice(&Class::IN.to_int().to_be_bytes());
        buffer.extend_from_slice(&3600u32.to_be_bytes());

        let mut rdata = crate::dns::name::encode_name("ns1.example.com").unwrap();
        rdata.extend_from_slice(&crate::dns::name::encode_name("admin.example.com").unwrap());
        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&7200u32.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&604_800u32.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes());

        buffer.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        buffer.extend_from_slice(&rdata);
    }

    buffer
}

/// Build a NOTIFY response with raw header `flags`, echoing an SOA question for `qname`.
fn build_notify_response(query_id: u16, flags: u16, qname: &str) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query_id.to_be_bytes());
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&crate::dns::name::encode_name(qname).unwrap());
    response.extend_from_slice(&Rtype::SOA.to_int().to_be_bytes());
    response.extend_from_slice(&Class::IN.to_int().to_be_bytes());

    response
}

/// Verify that `extract_soa_serial` reads the answer serial.
#[test]
fn extract_soa_serial_reads_the_answer_serial() {
    // 0x8400 = QR + AA, NOERROR.
    let response = build_flagged_soa_response(42, 0x8400, "example.com", true, 2026);
    assert_eq!(
        extract_soa_serial(42, &name("example.com"), &response).unwrap(),
        2026
    );
}

/// Verify that `extract_soa_serial` rejects id mismatch.
#[test]
fn extract_soa_serial_rejects_id_mismatch() {
    let response = build_flagged_soa_response(42, 0x8400, "example.com", true, 2026);

    assert!(
        extract_soa_serial(7, &name("example.com"), &response)
            .unwrap_err()
            .to_string()
            .contains("ID mismatch")
    );
}

/// Verify that `extract_soa_serial` rejects error rcode.
#[test]
fn extract_soa_serial_rejects_error_rcode() {
    // RCODE 5 (REFUSED)
    let response = build_flagged_soa_response(42, 0x8405, "example.com", true, 2026);
    assert!(matches!(
        extract_soa_serial(42, &name("example.com"), &response),
        Err(ParseResponseError::Rcode {
            rcode: OptRcode::REFUSED
        })
    ));
}

/// Verify that `extract_soa_serial` rejects missing qr bit.
#[test]
fn extract_soa_serial_rejects_missing_qr_bit() {
    let response = build_flagged_soa_response(42, 0x0400, "example.com", true, 2026);

    assert!(
        extract_soa_serial(42, &name("example.com"), &response)
            .unwrap_err()
            .to_string()
            .contains("QR bit")
    );
}

/// Verify that `extract_soa_serial` rejects truncated response.
#[test]
fn extract_soa_serial_rejects_truncated_response() {
    let response = build_flagged_soa_response(42, 0x8600, "example.com", true, 2026);
    assert!(matches!(
        extract_soa_serial(42, &name("example.com"), &response),
        Err(ParseResponseError::Truncated)
    ));
}

/// Verify that `extract_soa_serial` rejects answer without SOA.
#[test]
fn extract_soa_serial_rejects_answer_without_soa() {
    let response = build_flagged_soa_response(42, 0x8400, "example.com", false, 0);
    assert!(matches!(
        extract_soa_serial(42, &name("example.com"), &response),
        Err(ParseResponseError::NoSoa)
    ));
}

/// Verify that `extract_soa_serial` rejects a cache or another question.
#[test]
fn extract_soa_serial_rejects_a_cache_or_another_question() {
    // 0x8000 = QR without AA: a cache answered, not the secondary.
    let cached = build_flagged_soa_response(42, 0x8000, "example.com", true, 2026);

    assert!(matches!(
        extract_soa_serial(42, &name("example.com"), &cached),
        Err(ParseResponseError::NotAuthoritative)
    ));
    let other = build_flagged_soa_response(42, 0x8400, "other.com", true, 2026);

    assert!(matches!(
        extract_soa_serial(42, &name("example.com"), &other),
        Err(ParseResponseError::OtherQuestion)
    ));
}

/// Verify that `validate_notify_response` accepts matching noerror response.
#[test]
fn validate_notify_response_accepts_matching_noerror_response() {
    // 0xa000 = QR set + opcode NOTIFY, NOERROR.
    let response = build_notify_response(1234, 0xa000, "example.com");

    assert!(validate_notify_response(1234, &name("example.com"), &response).is_ok());
}

/// Verify that `validate_notify_response` rejects id mismatch.
#[test]
fn validate_notify_response_rejects_id_mismatch() {
    let response = build_notify_response(1234, 0xa000, "example.com");

    let error = validate_notify_response(5678, &name("example.com"), &response).unwrap_err();

    assert!(error.to_string().contains("ID mismatch"));
}

/// Verify that `validate_notify_response` rejects error rcode.
#[test]
fn validate_notify_response_rejects_error_rcode() {
    // 0xa005 adds RCODE 5 (REFUSED).
    let response = build_notify_response(1234, 0xa005, "example.com");

    let error = validate_notify_response(1234, &name("example.com"), &response).unwrap_err();

    assert!(error.to_string().contains("RCODE 5"));
}

/// Verify that `validate_notify_response` reports the RCODE of a refusal
/// that carries no question.
#[test]
fn validate_notify_response_reports_rcode_without_question() {
    // NSD 4.6 answers NOTIFY for a zone it does not serve with NOTAUTH
    // (RCODE 9) and an empty question section.
    let mut response = build_notify_response(1234, 0xa009, "example.com");
    response.truncate(12);
    response[4..6].copy_from_slice(&0u16.to_be_bytes());

    let error = validate_notify_response(1234, &name("example.com"), &response).unwrap_err();

    assert!(error.to_string().contains("RCODE 9"), "{error}");
}

/// Verify that `validate_notify_response` rejects another question.
#[test]
fn validate_notify_response_rejects_another_question() {
    let response = build_notify_response(1234, 0xa000, "other.com");

    let error = validate_notify_response(1234, &name("example.com"), &response).unwrap_err();

    assert!(error.to_string().contains("another question"), "{error}");
}
