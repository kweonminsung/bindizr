use domain::base::Message;
use domain::base::iana::{Class, Opcode, OptRcode, Rcode, TsigRcode};
use domain::rdata::tsig::Tsig;

use super::*;
use crate::dns::tsig;
use crate::model::tsig_key::TsigAlgorithm;

/// A truncated zone or later section receives only a header, without an invented OPT.
#[test]
fn unreadable_update_bodies_receive_header_only_formerr() {
    let valid = super::parser::tests::build_minimal_update_with_ztype(6);
    let mut unreadable_zone = valid[..12].to_vec();
    unreadable_zone.extend_from_slice(&[5, b'x']);
    let mut unreadable_update = valid.clone();
    unreadable_update[8..10].copy_from_slice(&1u16.to_be_bytes());
    let mut trailing_data = valid;
    trailing_data.push(0);

    for wire in [unreadable_zone, unreadable_update, trailing_data] {
        for limit in [ResponseLimit::UDP, ResponseLimit::STREAM] {
            let response =
                build_response(&wire, OptRcode::FORMERR, None, None, 300, limit).unwrap();
            let message = Message::from_octets(response.as_slice()).unwrap();

            assert_eq!(message.header().id(), 0x1234);
            assert_eq!(message.header().opcode(), Opcode::UPDATE);
            assert!(message.header().qr());
            assert_eq!(message.header().rcode(), Rcode::FORMERR);
            assert_eq!(response.len(), 12);
            assert_eq!(message.header_counts().qdcount(), 0);
            assert_eq!(message.header_counts().arcount(), 0);
        }
    }
}

/// Verify that `build_response` echoes request header and question.
#[test]
fn build_response_echoes_request_header_and_question() {
    let query = super::parser::tests::build_minimal_update_with_ztype(6);

    let response = build_response(
        &query,
        OptRcode::REFUSED,
        None,
        None,
        300,
        crate::dns::message::ResponseLimit::udp(512),
    )
    .unwrap();

    let message = Message::from_octets(&response[..]).unwrap();
    let header = message.header();

    assert_eq!(header.id(), 0x1234);
    assert!(header.qr());
    assert_eq!(header.opcode(), Opcode::UPDATE);
    assert_eq!(header.rcode(), Rcode::REFUSED);
    assert_eq!(message.header_counts().qdcount(), 1);
    assert_eq!(message.header_counts().arcount(), 0);
}

/// Verify that `build_response` answers an EDNS request with an OPT
/// carrying the extended rcode (RFC 6891, Section 6.1.1).
#[test]
fn build_response_echoes_an_opt_with_the_extended_rcode() {
    let mut query = super::parser::tests::build_minimal_update_with_ztype(6);
    query[10..12].copy_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let response = build_response(
        &query,
        OptRcode::BADVERS,
        None,
        None,
        300,
        crate::dns::message::ResponseLimit::udp(1232),
    )
    .unwrap();

    let message = Message::from_octets(&response[..]).unwrap();
    let opt = message.opt().expect("the OPT is echoed");

    assert_eq!(opt.rcode(message.header()), OptRcode::BADVERS);
    assert_eq!(opt.udp_payload_size(), 1232);
}

/// Verify that `build_response` signs with request mac chain.
#[test]
fn build_response_signs_with_request_mac_chain() {
    let query = crate::dns::tsig::tests::build_signed_update(
        TsigAlgorithm::HmacSha256,
        crate::dns::tsig::tests::now_secs(),
    );
    let key = crate::dns::tsig::tests::test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    let signer = tsig::verify_tsig(&query, Some(key)).unwrap();

    let response = build_response(
        &query,
        OptRcode::NOERROR,
        None,
        Some(signer),
        300,
        crate::dns::message::ResponseLimit::udp(512),
    )
    .unwrap();

    let message = Message::from_octets(&response[..]).unwrap();

    assert_eq!(message.header().rcode(), Rcode::NOERROR);
    let tsig_record = message
        .additional()
        .unwrap()
        .limit_to::<Tsig<_, _>>()
        .last()
        .unwrap()
        .unwrap();
    let data = tsig_record.data();

    assert_eq!(data.error(), TsigRcode::NOERROR);
    assert_eq!(data.fudge(), 300);

    // The request's MAC is the last rdata field before the trailing original
    // ID, error, and other-len (2 bytes each).
    let request_mac = query[query.len() - 6 - 32..query.len() - 6].to_vec();

    // The unsigned build supplies the response before TSIG, including ARCOUNT.
    let unsigned = build_response(
        &query,
        OptRcode::NOERROR,
        None,
        None,
        300,
        crate::dns::message::ResponseLimit::udp(512),
    )
    .unwrap();

    // RFC 8945, Section 4.3.3: request MAC, unsigned response, TSIG variables.
    let mut digest = Vec::new();
    digest.extend_from_slice(&(request_mac.len() as u16).to_be_bytes());
    digest.extend_from_slice(&request_mac);
    digest.extend_from_slice(&unsigned);
    digest.extend_from_slice(&crate::dns::tsig::tests::encode_name("update-key"));
    digest.extend_from_slice(&Class::ANY.to_int().to_be_bytes());
    digest.extend_from_slice(&0u32.to_be_bytes());
    digest.extend_from_slice(&crate::dns::tsig::tests::encode_name("hmac-sha256"));
    digest.extend_from_slice(&crate::dns::tsig::tests::encode_u48(u64::from(
        data.time_signed(),
    )));
    digest.extend_from_slice(&data.fudge().to_be_bytes());
    digest.extend_from_slice(&0u16.to_be_bytes()); // error
    digest.extend_from_slice(&0u16.to_be_bytes()); // other len

    let expected = crate::dns::tsig::tests::hmac_sign(TsigAlgorithm::HmacSha256, &digest);

    assert_eq!(*data.mac(), &expected[..]);
}
/// UPDATE replies preserve MACs within the UDP limit.
#[test]
fn update_responses_fit_udp_with_long_compressed_key_names() {
    use std::str::FromStr;

    use domain::base::{Name, Rtype};
    use domain::tsig::ClientTransaction;

    use crate::dns::message;
    use crate::model::tsig_key::{TsigAlgorithm, TsigKey};
    let name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let key = TsigKey {
        name: name.clone(),
        ..crate::dns::tsig::tests::test_key(TsigAlgorithm::HmacSha512)
    }
    .to_signing_key()
    .unwrap();

    for size in [None, Some(512), Some(1232)] {
        let mut builder = message::build_response();
        builder.header_mut().set_opcode(Opcode::UPDATE);
        let mut question = builder.question();
        question
            .push((Name::<Vec<u8>>::from_str(&name).unwrap(), Rtype::SOA))
            .unwrap();
        let mut additional = question.additional();

        if let Some(size) = size {
            additional
                .opt(|opt| {
                    opt.set_udp_payload_size(size);
                    Ok(())
                })
                .unwrap();
        }

        let client =
            ClientTransaction::request(key.clone(), &mut additional, Time48::now()).unwrap();
        let request = additional.finish().into_target();
        let signer = crate::dns::tsig::verify_tsig(&request, Some(key.clone())).unwrap();

        for rcode in [
            OptRcode::NOERROR,
            OptRcode::REFUSED,
            OptRcode::FORMERR,
            OptRcode::SERVFAIL,
        ] {
            let response = build_response(
                &request,
                rcode,
                None,
                Some(signer.clone()),
                300,
                crate::dns::message::ResponseLimit::udp(size.unwrap_or(512)),
            )
            .unwrap();

            assert!(response.len() <= size.unwrap_or(512) as usize);
            client
                .answer(
                    &mut Message::from_octets(response.clone()).unwrap(),
                    Time48::now(),
                )
                .unwrap();
            crate::dns::tsig::tests::assert_response_mac(
                &request,
                &response,
                TsigAlgorithm::HmacSha512,
            );
        }
    }
}
