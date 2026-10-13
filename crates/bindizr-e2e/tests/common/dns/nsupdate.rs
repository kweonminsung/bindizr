//! Building and sending RFC 2136 UPDATE messages.

use std::str::FromStr;

use domain::{
    base::{
        MessageBuilder, Name, Record, Rtype, Ttl, UnknownRecordData,
        iana::{Class, Opcode, OptRcode, Rcode},
        message_builder::AdditionalBuilder,
    },
    rdata::{A, Cname, Dname, Ns, Soa},
};

use super::{
    exchange_request, exchange_tcp, exchange_udp, parse_name,
    tsig::{SigningKey, is_signed},
};

/// One record of an update section, in the class that gives it its meaning
/// (RFC 2136, Section 2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpdateRecord {
    /// CLASS IN: add raw RDATA.
    AddRecord {
        name: String,
        rtype: Rtype,
        ttl: u32,
        rdata: Vec<u8>,
    },
    /// CLASS IN: replace the zone SOA when its serial advances.
    AddSoa {
        name: String,
        ttl: u32,
        soa: Soa<Name<Vec<u8>>>,
    },
    /// CLASS IN: add this address record.
    AddA {
        name: String,
        ttl: u32,
        addr: String,
    },
    /// CLASS IN: add this CNAME.
    AddCname {
        name: String,
        ttl: u32,
        target: String,
    },
    /// CLASS IN: add this DNAME.
    AddDname {
        name: String,
        ttl: u32,
        target: String,
    },
    /// CLASS ANY: delete the record set.
    DeleteRecordSet { name: String, rtype: Rtype },
    /// CLASS NONE: delete just this address record.
    DeleteA { name: String, addr: String },
    /// CLASS NONE: delete just this NS record.
    DeleteNs { name: String, target: String },
    /// CLASS NONE: delete a record whose wire data the builder need not understand.
    DeleteRecord {
        name: String,
        rtype: Rtype,
        rdata: Vec<u8>,
    },
}

/// One prerequisite (RFC 2136, Section 2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrerequisiteRecord {
    /// CLASS ANY, TYPE ANY: the owner name must exist.
    NameInUse { name: String },
    /// CLASS NONE, TYPE ANY: the owner name must not exist.
    NameNotInUse { name: String },
    /// CLASS ANY: the record set must exist.
    RecordSetInUse { name: String, rtype: Rtype },
    /// CLASS NONE: the record set must not exist.
    RecordSetNotInUse { name: String, rtype: Rtype },
    /// CLASS IN, TTL 0: with the others of its name, these A values must be
    /// exactly the zone's (RFC 2136, Section 3.2.3).
    AEquals { name: String, addr: String },
    /// CLASS IN, TTL 0: the zone's SOA must be exactly this one.
    SoaEquals {
        name: String,
        soa: Soa<Name<Vec<u8>>>,
    },
    /// CLASS IN, TTL 0: a wire value contributing to exact RRset equality.
    RecordEquals {
        name: String,
        rtype: Rtype,
        rdata: Vec<u8>,
    },
}

/// Send a UDP UPDATE, checking the response ID and optional TSIG.
pub(crate) fn send_update_udp(
    port: u16,
    zone: &str,
    prerequisites: &[PrerequisiteRecord],
    updates: &[UpdateRecord],
    key: Option<&SigningKey>,
) -> Result<Rcode, String> {
    let query_id = (std::process::id() as u16)
        .wrapping_add(port)
        .wrapping_add(1);
    let request = build_update(query_id, zone, Class::IN, prerequisites, updates)?;
    let response = exchange_request(request, key, |message| exchange_udp(port, message))?;
    Ok(response.header().rcode())
}

/// Send a TCP UPDATE, checking the response ID and optional TSIG.
pub(crate) fn send_update_tcp(
    port: u16,
    zone: &str,
    prerequisites: &[PrerequisiteRecord],
    updates: &[UpdateRecord],
    key: Option<&SigningKey>,
) -> Result<Rcode, String> {
    let query_id = (std::process::id() as u16).wrapping_add(port);
    let request = build_update(query_id, zone, Class::IN, prerequisites, updates)?;
    let response = exchange_request(request, key, |message| exchange_tcp(port, message))?;
    Ok(response.header().rcode())
}

/// Send a signed two-zone UPDATE, invalid under RFC 2136, Section 3.1.1.
pub(crate) fn send_signed_update_with_two_zones(
    port: u16,
    zone: &str,
    key: &SigningKey,
) -> Result<(Rcode, bool), String> {
    let query_id = (std::process::id() as u16)
        .wrapping_add(port)
        .wrapping_add(2);
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(query_id);
    builder.header_mut().set_opcode(Opcode::UPDATE);
    let mut question = builder.question();
    for _ in 0..2 {
        question
            .push((&parse_name(zone)?, Rtype::SOA, Class::IN))
            .map_err(|e| e.to_string())?;
    }
    let response = exchange_request(question.additional(), Some(key), |message| {
        exchange_udp(port, message)
    })?;
    Ok((response.header().rcode(), is_signed(&response)?))
}

/// Send a signed UPDATE with the specified EDNS version.
pub(crate) fn send_signed_update_with_edns_version(
    port: u16,
    zone: &str,
    key: &SigningKey,
    version: u8,
) -> Result<(OptRcode, bool), String> {
    let query_id = (std::process::id() as u16)
        .wrapping_add(port)
        .wrapping_add(3);
    let mut builder = build_update(query_id, zone, Class::IN, &[], &[])?;
    builder
        .opt(|opt| {
            opt.set_udp_payload_size(4096);
            opt.set_version(version);
            Ok(())
        })
        .map_err(|e| e.to_string())?;
    let response = exchange_request(builder, Some(key), |message| exchange_udp(port, message))?;
    let rcode = response
        .opt()
        .map_or(OptRcode::from(response.header().rcode()), |opt| {
            opt.rcode(response.header())
        });
    Ok((rcode, is_signed(&response)?))
}

/// Build zone, prerequisite, and update sections (RFC 2136, Section 2.1).
pub(crate) fn build_update(
    query_id: u16,
    zone: &str,
    zone_class: Class,
    prerequisites: &[PrerequisiteRecord],
    updates: &[UpdateRecord],
) -> Result<AdditionalBuilder<Vec<u8>>, String> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(query_id);
    builder.header_mut().set_opcode(Opcode::UPDATE);

    let mut question = builder.question();
    question
        .push((&parse_name(zone)?, Rtype::SOA, zone_class))
        .map_err(|e| e.to_string())?;

    let mut answer = question.answer();
    for prerequisite in prerequisites {
        match prerequisite {
            PrerequisiteRecord::NameInUse { name: owner } => answer
                .push(empty_record(owner, Rtype::ANY, Class::ANY)?)
                .map_err(|e| e.to_string())?,
            PrerequisiteRecord::NameNotInUse { name: owner } => answer
                .push(empty_record(owner, Rtype::ANY, Class::NONE)?)
                .map_err(|e| e.to_string())?,
            PrerequisiteRecord::RecordSetInUse { name: owner, rtype } => answer
                .push(empty_record(owner, *rtype, Class::ANY)?)
                .map_err(|e| e.to_string())?,
            PrerequisiteRecord::RecordSetNotInUse { name: owner, rtype } => answer
                .push(empty_record(owner, *rtype, Class::NONE)?)
                .map_err(|e| e.to_string())?,
            PrerequisiteRecord::SoaEquals { name: owner, soa } => answer
                .push(Record::new(
                    parse_name(owner)?,
                    Class::IN,
                    Ttl::ZERO,
                    soa.clone(),
                ))
                .map_err(|e| e.to_string())?,
            PrerequisiteRecord::AEquals { name: owner, addr } => {
                let data = A::from_str(addr).map_err(|e| e.to_string())?;
                answer
                    .push(Record::new(parse_name(owner)?, Class::IN, Ttl::ZERO, data))
                    .map_err(|e| e.to_string())?;
            }
            PrerequisiteRecord::RecordEquals { name, rtype, rdata } => {
                let data = UnknownRecordData::from_octets(*rtype, rdata.clone())
                    .map_err(|e| e.to_string())?;
                answer
                    .push(Record::new(parse_name(name)?, Class::IN, Ttl::ZERO, data))
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    let mut authority = answer.authority();
    for update in updates {
        match update {
            UpdateRecord::AddRecord {
                name,
                rtype,
                ttl,
                rdata,
            } => {
                let data = UnknownRecordData::from_octets(*rtype, rdata.clone())
                    .map_err(|e| e.to_string())?;
                authority
                    .push(Record::new(
                        parse_name(name)?,
                        Class::IN,
                        Ttl::from_secs(*ttl),
                        data,
                    ))
                    .map_err(|e| e.to_string())?;
            }
            UpdateRecord::AddSoa { name, ttl, soa } => authority
                .push(Record::new(
                    parse_name(name)?,
                    Class::IN,
                    Ttl::from_secs(*ttl),
                    soa.clone(),
                ))
                .map_err(|e| e.to_string())?,
            UpdateRecord::AddA {
                name: owner,
                ttl,
                addr,
            } => {
                let data = A::from_str(addr).map_err(|e| e.to_string())?;
                authority
                    .push(Record::new(
                        parse_name(owner)?,
                        Class::IN,
                        Ttl::from_secs(*ttl),
                        data,
                    ))
                    .map_err(|e| e.to_string())?;
            }
            UpdateRecord::AddCname {
                name: owner,
                ttl,
                target,
            } => {
                let data = Cname::new(parse_name(target)?);
                authority
                    .push(Record::new(
                        parse_name(owner)?,
                        Class::IN,
                        Ttl::from_secs(*ttl),
                        data,
                    ))
                    .map_err(|e| e.to_string())?;
            }
            UpdateRecord::AddDname {
                name: owner,
                ttl,
                target,
            } => {
                let data = Dname::new(parse_name(target)?);
                authority
                    .push(Record::new(
                        parse_name(owner)?,
                        Class::IN,
                        Ttl::from_secs(*ttl),
                        data,
                    ))
                    .map_err(|e| e.to_string())?;
            }
            UpdateRecord::DeleteRecordSet { name: owner, rtype } => authority
                .push(empty_record(owner, *rtype, Class::ANY)?)
                .map_err(|e| e.to_string())?,
            UpdateRecord::DeleteRecord { name, rtype, rdata } => {
                let data = UnknownRecordData::from_octets(*rtype, rdata.clone())
                    .map_err(|e| e.to_string())?;
                authority
                    .push(Record::new(parse_name(name)?, Class::NONE, Ttl::ZERO, data))
                    .map_err(|e| e.to_string())?;
            }
            UpdateRecord::DeleteNs {
                name: owner,
                target,
            } => {
                let data = Ns::new(parse_name(target)?);
                authority
                    .push(Record::new(
                        parse_name(owner)?,
                        Class::NONE,
                        Ttl::ZERO,
                        data,
                    ))
                    .map_err(|e| e.to_string())?;
            }
            UpdateRecord::DeleteA { name: owner, addr } => {
                let data = A::from_str(addr).map_err(|e| e.to_string())?;
                authority
                    .push(Record::new(
                        parse_name(owner)?,
                        Class::NONE,
                        Ttl::ZERO,
                        data,
                    ))
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    // The TSIG, when there is one, goes in the additional section.
    Ok(authority.additional())
}

/// A record carrying no rdata, built from an rtype the builder need not know.
type EmptyRecord = Record<Name<Vec<u8>>, UnknownRecordData<Vec<u8>>>;

/// A record with empty rdata and TTL 0 — the shape every delete-record-set and
/// name-existence entry takes.
fn empty_record(owner: &str, rtype: Rtype, class: Class) -> Result<EmptyRecord, String> {
    let data = UnknownRecordData::from_octets(rtype, Vec::new()).map_err(|e| e.to_string())?;
    Ok(Record::new(parse_name(owner)?, class, Ttl::ZERO, data))
}
