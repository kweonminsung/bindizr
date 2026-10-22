//! Compose outbound questions, leaving finalization to the caller when signing is optional.

use domain::base::{
    MessageBuilder, Name,
    iana::{Opcode, Rtype},
    message_builder::AdditionalBuilder,
    opt::keepalive::TcpKeepalive,
};

use super::EDNS_UDP_PAYLOAD_SIZE;
use crate::dns::tsig::TsigSigningKey;

/// Build a random-ID question with optional EDNS; leave additional open for signing.
pub fn build_question(
    opcode: Opcode,
    aa: bool,
    rd: bool,
    qname: &Name<Vec<u8>>,
    rtype: Rtype,
    edns_udp_payload_size: Option<u16>,
) -> (u16, AdditionalBuilder<Vec<u8>>) {
    let query_id = rand::random::<u16>();

    let mut builder = MessageBuilder::new_vec();
    let header = builder.header_mut();
    header.set_id(query_id);
    header.set_opcode(opcode);
    header.set_aa(aa);
    header.set_rd(rd);

    let mut question = builder.question();
    question
        .push((qname, rtype))
        .expect("one question fits an unlimited message");

    let mut additional = question.additional();

    if let Some(udp_payload_size) = edns_udp_payload_size {
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(udp_payload_size);
                Ok(())
            })
            .expect("one OPT record fits an unlimited message");
    }

    (query_id, additional)
}

/// Build an AXFR query whose OPT asks the primary to keep the connection for
/// the transfers that follow (RFC 7828, Section 3.2.1; RFC 9103, Section 6).
pub fn build_axfr_query(qname: &Name<Vec<u8>>) -> (u16, Vec<u8>) {
    let (query_id, mut builder) =
        build_question(Opcode::QUERY, false, false, qname, Rtype::AXFR, None);
    builder
        .opt(|opt| {
            opt.set_udp_payload_size(EDNS_UDP_PAYLOAD_SIZE);
            opt.push(&TcpKeepalive::new(None))
        })
        .expect("one OPT record fits an unlimited message");

    (query_id, builder.finish())
}

/// Add EDNS when the final signed NOTIFY would exceed 512 octets (RFC 1035, Section 4.2.1).
pub fn build_notify_query(
    qname: &Name<Vec<u8>>,
    key: Option<&TsigSigningKey>,
) -> (u16, AdditionalBuilder<Vec<u8>>) {
    let (id, mut builder) = build_question(Opcode::NOTIFY, true, false, qname, Rtype::SOA, None);

    if key.is_some_and(|key| {
        builder.as_slice().len() + usize::from(key.as_ref().compose_len())
            > usize::from(crate::dns::message::UDP_PAYLOAD_SIZE_WITHOUT_EDNS)
    }) {
        builder
            .opt(|opt| {
                opt.set_udp_payload_size(EDNS_UDP_PAYLOAD_SIZE);
                Ok(())
            })
            .expect("one OPT record fits an unlimited message");
    }

    (id, builder)
}
