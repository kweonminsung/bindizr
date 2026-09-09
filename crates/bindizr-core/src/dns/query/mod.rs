//! Outbound queries and the responses they expect: building a question,
//! and reading back a NOTIFY acknowledgement, a SOA serial, a parent's DS
//! RRset, or a zone's NS names.

use domain::{
    base::{
        Message, MessageBuilder, Name, ToName,
        iana::{Class, Opcode, Rcode, Rtype},
        rdata::ComposeRecordData,
    },
    rdata::{Ds, Ns, Soa},
};

/// EDNS0 payload size advertised where the answer may outgrow 512 bytes (a
/// TLD's NS RRset): the DNS flag day 2020 value.
pub const EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

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

/// [`build_question`] for a standard query carrying an EDNS0 OPT record
/// (RFC 6891) that advertises [`EDNS_UDP_PAYLOAD_SIZE`].
pub fn build_edns_question(rd: bool, qname: &Name<Vec<u8>>, rtype: Rtype) -> (u16, Vec<u8>) {
    let query_id = rand::random::<u16>();

    let mut builder = MessageBuilder::new_vec();
    let header = builder.header_mut();
    header.set_id(query_id);
    header.set_opcode(Opcode::QUERY);
    header.set_rd(rd);

    let mut question = builder.question();
    question
        .push((qname, rtype))
        .expect("composing into a Vec cannot run out of space");
    let mut additional = question.additional();
    additional
        .opt(|opt| {
            opt.set_udp_payload_size(EDNS_UDP_PAYLOAD_SIZE);
            Ok(())
        })
        .expect("composing into a Vec cannot run out of space");

    (query_id, additional.finish())
}

/// Whether a response carries the TC flag: the answer did not fit the UDP
/// payload and is to be asked again over TCP (RFC 1035, Section 4.2.1).
pub fn is_truncated(response: &[u8]) -> bool {
    Message::from_octets(response).is_ok_and(|message| message.header().tc())
}

/// `parse_response`, plus the echoed question must be ours (`qname`, `rtype`,
/// class IN).
fn parse_answer<'a>(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    rtype: Rtype,
    response: &'a [u8],
) -> Result<Message<&'a [u8]>, String> {
    let message = parse_response(query_id, response)?;
    let question = message
        .sole_question()
        .map_err(|e| format!("malformed question section: {}", e))?;
    if !question.qname().name_eq(qname)
        || question.qtype() != rtype
        || question.qclass() != Class::IN
    {
        return Err("response answers another question".to_string());
    }
    Ok(message)
}

/// `parse_answer`, and the answer must be the server's own (AA), not a
/// cache's.
fn parse_authoritative_answer<'a>(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    rtype: Rtype,
    response: &'a [u8],
) -> Result<Message<&'a [u8]>, String> {
    let message = parse_answer(query_id, qname, rtype, response)?;
    if !message.header().aa() {
        return Err("response is not authoritative".to_string());
    }
    Ok(message)
}

/// Check a response answers our question: our id, QR set, not truncated.
/// The RCODE is the caller's, since NXDOMAIN answers some questions.
fn parse_response(query_id: u16, response: &[u8]) -> Result<Message<&[u8]>, String> {
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
    Ok(message)
}

/// One answer RR from a zone-transfer response, in presentation form.
#[derive(Debug)]
pub struct TransferRr {
    /// Owner name as an absolute presentation name (trailing dot).
    pub name: String,
    pub rtype: Rtype,
    pub ttl: u32,
    /// RDATA in standard presentation form.
    pub rdata: String,
}

/// Validate one AXFR response message and collect every answer RR; the
/// caller assembles the stream (SOA-delimited per RFC 5936, Section 2.2).
/// The `first` message must echo the question and be authoritative; later
/// ones may omit the question (RFC 5936, Sections 2.2.1 and 2.2.2).
pub fn extract_transfer_rrs(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    first: bool,
    response: &[u8],
) -> Result<Vec<TransferRr>, String> {
    use domain::rdata::AllRecordData;

    let message = if first {
        parse_authoritative_answer(query_id, qname, Rtype::AXFR, response)?
    } else if parse_response(query_id, response)?
        .header_counts()
        .qdcount()
        == 1
    {
        parse_answer(query_id, qname, Rtype::AXFR, response)?
    } else {
        parse_response(query_id, response)?
    };
    if message.header().rcode() != Rcode::NOERROR {
        return Err(format!("RCODE {}", message.header().rcode().to_int()));
    }

    let answer = message
        .answer()
        .map_err(|e| format!("malformed answer section: {}", e))?;
    let mut rrs = Vec::new();
    for rr in answer.limit_to::<AllRecordData<_, _>>() {
        let rr = rr.map_err(|e| format!("malformed answer record: {}", e))?;
        // A zone transfer is single-class; rendering would rewrite any other
        // class as IN.
        if rr.class() != Class::IN {
            return Err(format!(
                "transfer carries a class {} record for {}",
                rr.class(),
                rr.owner()
            ));
        }
        // Every embedded rdata name renders absolute except the SRV
        // target; left bare, re-parsing would requalify it.
        let rdata = match rr.data() {
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
        rrs.push(TransferRr {
            // Display omits the root dot; the absolute form keeps the
            // import parser from re-qualifying the name.
            name: format!("{}.", rr.owner()),
            rtype: rr.rtype(),
            ttl: rr.ttl().as_secs(),
            rdata,
        });
    }
    Ok(rrs)
}

/// Check that a NOTIFY was acknowledged by the server we asked.
pub fn validate_notify_response(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<(), String> {
    // The response copies the request's question (RFC 1996, Section 3.7).
    let message =
        parse_answer(query_id, qname, Rtype::SOA, response).map_err(|e| format!("NOTIFY {}", e))?;
    let header = message.header();
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

/// Read an authoritative SOA answer's serial: the serial a secondary itself
/// serves for `qname`, which a cache's answer would not be.
pub fn extract_soa_serial(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<u32, String> {
    let message = parse_authoritative_answer(query_id, qname, Rtype::SOA, response)?;
    if message.header().rcode() != Rcode::NOERROR {
        return Err(format!("RCODE {}", message.header().rcode().to_int()));
    }

    let answer = message
        .answer()
        .map_err(|e| format!("malformed answer section: {}", e))?;
    answer
        .limit_to::<Soa<_>>()
        .filter_map(|rr| rr.ok())
        .find(|rr| rr.owner().name_eq(qname))
        .map(|rr| rr.data().serial().into_int())
        .ok_or_else(|| "no SOA record in answer".to_string())
}

/// The DS RRset a parent-zone server holds for a child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRrset {
    /// The DS records at the child's name, ordered by key tag then RDATA and
    /// deduplicated.
    pub records: Vec<DsRr>,
    /// The RRset's TTL: how long a cache may keep serving these DS records.
    pub ttl: u32,
}

impl DsRrset {
    /// Key tags of the keys the records name, ascending and deduplicated.
    pub fn key_tags(&self) -> Vec<u16> {
        let mut key_tags: Vec<u16> = self.records.iter().map(|record| record.key_tag).collect();
        key_tags.dedup();
        key_tags
    }
}

/// One DS record of a parent's answer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DsRr {
    pub key_tag: u16,
    pub digest_type: u8,
    /// The RDATA of RFC 4034, Section 5.1; matched whole, since keys can
    /// share a 16-bit tag.
    pub rdata: Vec<u8>,
}

/// Read a parent server's answer to a DS question: `Some` with the RRset,
/// `None` for an authoritative NODATA or NXDOMAIN. A non-authoritative
/// answer is refused: a cache may lag the parent.
pub fn extract_ds_rrset(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<Option<DsRrset>, String> {
    let message = parse_authoritative_answer(query_id, qname, Rtype::DS, response)?;
    match message.header().rcode() {
        Rcode::NOERROR => {}
        Rcode::NXDOMAIN => return require_parent_soa(&message, qname).map(|_| None),
        rcode => return Err(format!("RCODE {}", rcode.to_int())),
    }

    let answer = message
        .answer()
        .map_err(|e| format!("malformed answer section: {}", e))?;
    let mut records = Vec::new();
    let mut ttl: Option<u32> = None;
    for rr in answer.limit_to::<Ds<_>>() {
        let rr = rr.map_err(|e| format!("malformed answer record: {}", e))?;
        // Only DS records at the child's own name are its delegation.
        if !rr.owner().name_eq(qname) {
            continue;
        }
        let mut rdata = Vec::new();
        rr.data()
            .compose_rdata(&mut rdata)
            .expect("composing into a Vec cannot run out of space");
        records.push(DsRr {
            key_tag: rr.data().key_tag(),
            digest_type: rr.data().digest_type().to_int(),
            rdata,
        });
        ttl = Some(ttl.map_or(rr.ttl().as_secs(), |t| t.min(rr.ttl().as_secs())));
    }
    let Some(ttl) = ttl else {
        return require_parent_soa(&message, qname).map(|_| None);
    };
    records.sort();
    records.dedup();
    Ok(Some(DsRrset { records, ttl }))
}

/// A negative DS answer counts only with a strict ancestor's SOA in the
/// authority section (RFC 2308, Section 2): the child's own server says
/// NODATA just as authoritatively.
fn require_parent_soa(message: &Message<&[u8]>, qname: &Name<Vec<u8>>) -> Result<(), String> {
    let authority = message
        .authority()
        .map_err(|e| format!("malformed authority section: {}", e))?;
    for rr in authority.limit_to::<Soa<_>>() {
        let rr = rr.map_err(|e| format!("malformed authority record: {}", e))?;
        if qname.ends_with(rr.owner()) && !qname.name_eq(rr.owner()) {
            return Ok(());
        }
    }
    Err("negative answer carries no SOA of a parent zone".to_string())
}

/// Read a resolver's NS answer as absolute names (trailing dot), so a later
/// lookup skips search-list expansion; empty for NODATA or NXDOMAIN.
pub fn extract_ns_names(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<Vec<String>, String> {
    let message = parse_answer(query_id, qname, Rtype::NS, response)?;
    match message.header().rcode() {
        Rcode::NOERROR => {}
        Rcode::NXDOMAIN => return Ok(Vec::new()),
        rcode => return Err(format!("RCODE {}", rcode.to_int())),
    }

    let answer = message
        .answer()
        .map_err(|e| format!("malformed answer section: {}", e))?;
    let mut names = Vec::new();
    for rr in answer.limit_to::<Ns<_>>() {
        let rr = rr.map_err(|e| format!("malformed answer record: {}", e))?;
        // A CNAME answer carries the target's NS set too; only the name's own
        // NS records say it is a zone apex.
        if !rr.owner().name_eq(qname) {
            continue;
        }
        names.push(rr.data().nsdname().fmt_with_dot().to_string());
    }
    Ok(names)
}

#[cfg(test)]
mod tests;
