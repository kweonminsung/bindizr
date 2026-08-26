//! Outbound queries and the responses they expect: building a question,
//! and reading back a NOTIFY acknowledgement or a SOA serial.

use domain::{
    base::{
        Message, MessageBuilder, Name,
        iana::{Opcode, Rcode, Rtype},
    },
    rdata::Soa,
};

/// Build a single-SOA-question DNS message with a random id, returning
/// `(query_id, wire bytes)`.
pub fn build_question(opcode: Opcode, aa: bool, qname: &Name<Vec<u8>>) -> (u16, Vec<u8>) {
    let query_id = rand::random::<u16>();

    let mut builder = MessageBuilder::new_vec();
    let header = builder.header_mut();
    header.set_id(query_id);
    header.set_opcode(opcode);
    header.set_aa(aa);

    let mut question = builder.question();
    // Composing one question into a Vec cannot fail.
    question
        .push((qname, Rtype::SOA))
        .expect("composing into a Vec cannot run out of space");

    (query_id, question.finish())
}

/// Check that a NOTIFY was acknowledged by the server we asked.
pub fn validate_notify_response(query_id: u16, response: &[u8]) -> Result<(), String> {
    let message = Message::from_octets(response)
        .map_err(|e| format!("NOTIFY response is malformed: {}", e))?;

    let header = message.header();
    if header.id() != query_id {
        return Err(format!(
            "NOTIFY response ID mismatch: expected {}, got {}",
            query_id,
            header.id()
        ));
    }

    if !header.qr() {
        return Err("NOTIFY response does not have QR bit set".to_string());
    }

    if header.opcode() != Opcode::NOTIFY {
        return Err(format!(
            "NOTIFY response opcode mismatch: expected {}, got {}",
            Opcode::NOTIFY.to_int(),
            header.opcode().to_int()
        ));
    }

    if header.rcode() != Rcode::NOERROR {
        return Err(format!(
            "NOTIFY response returned RCODE {}",
            header.rcode().to_int()
        ));
    }

    Ok(())
}

/// Validates a SOA query response and extracts the serial from the first SOA
/// record in the answer section.
pub fn extract_soa_serial(query_id: u16, response: &[u8]) -> Result<u32, String> {
    let message =
        Message::from_octets(response).map_err(|e| format!("malformed response: {}", e))?;

    let header = message.header();
    if header.id() != query_id {
        return Err(format!(
            "response ID mismatch: expected {}, got {}",
            query_id,
            header.id()
        ));
    }
    if !header.qr() {
        return Err("response does not have QR bit set".to_string());
    }
    if header.tc() {
        return Err("truncated response".to_string());
    }
    if header.rcode() != Rcode::NOERROR {
        return Err(format!("RCODE {}", header.rcode().to_int()));
    }

    let answer = message
        .answer()
        .map_err(|e| format!("malformed answer section: {}", e))?;
    answer
        .limit_to::<Soa<_>>()
        .find_map(|record| record.ok())
        .map(|record| record.data().serial().into_int())
        .ok_or_else(|| "no SOA record in answer".to_string())
}
