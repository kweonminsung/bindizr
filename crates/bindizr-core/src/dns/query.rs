//! Outbound queries and the responses they expect: building a question,
//! and reading back a NOTIFY acknowledgement or a SOA serial.

use domain::{
    base::{
        Message, MessageBuilder, Name,
        iana::{Opcode, Rcode, Rtype},
    },
    rdata::{Ds, Soa},
};

/// Build a single-question DNS message with a random id, returning
/// `(query_id, wire bytes)`. `rd` asks a resolver to recurse.
pub fn build_question(
    opcode: Opcode,
    aa: bool,
    rd: bool,
    qname: &Name<Vec<u8>>,
    rtype: Rtype,
) -> (u16, Vec<u8>) {
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
        .expect("composing into a Vec cannot run out of space");

    (query_id, question.finish())
}

/// One DS record from a response's answer section; digest in uppercase hex.
pub struct DsAnswer {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
    /// Answer TTL: how long resolvers may still serve the previous DS set.
    pub ttl: u32,
}

/// Validate a DS query response and collect every DS record in its answer
/// section; empty when the delegation carries no DS.
pub fn extract_ds_answers(query_id: u16, response: &[u8]) -> Result<Vec<DsAnswer>, String> {
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
    let mut records = Vec::new();
    for record in answer.limit_to::<Ds<_>>() {
        let record = record.map_err(|e| format!("malformed DS record: {}", e))?;
        let data = record.data();
        records.push(DsAnswer {
            key_tag: data.key_tag(),
            algorithm: data.algorithm().to_int(),
            digest_type: data.digest_type().to_int(),
            digest: hex::encode_upper(data.digest()),
            ttl: record.ttl().as_secs(),
        });
    }
    Ok(records)
}

/// One answer record from a zone-transfer response, in presentation form.
#[derive(Debug)]
pub struct TransferRecord {
    /// Owner name as an absolute presentation name (trailing dot).
    pub name: String,
    pub rtype: Rtype,
    pub ttl: u32,
    /// RDATA in standard presentation form.
    pub rdata: String,
}

/// Validate one AXFR response message and collect every answer record; the
/// caller assembles the stream (SOA-delimited per RFC 5936, Section 2.2).
pub fn extract_transfer_records(
    query_id: u16,
    response: &[u8],
) -> Result<Vec<TransferRecord>, String> {
    use domain::rdata::AllRecordData;

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
    let mut records = Vec::new();
    for record in answer.limit_to::<AllRecordData<_, _>>() {
        let record = record.map_err(|e| format!("malformed answer record: {}", e))?;
        // Every embedded rdata name renders absolute except the SRV
        // target; left bare, re-parsing would requalify it.
        let rdata = match record.data() {
            AllRecordData::Srv(srv) => {
                let target = srv.target().to_string();
                let target = if target == "." {
                    target
                } else {
                    format!("{}.", target)
                };
                format!(
                    "{} {} {} {}",
                    srv.priority(),
                    srv.weight(),
                    srv.port(),
                    target
                )
            }
            data => data.to_string(),
        };
        records.push(TransferRecord {
            // Display omits the root dot; the absolute form keeps the
            // import parser from re-qualifying the name.
            name: format!("{}.", record.owner()),
            rtype: record.rtype(),
            ttl: record.ttl().as_secs(),
            rdata,
        });
    }
    Ok(records)
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
