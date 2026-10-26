//! Decode parent DS answers and validate their negative-answer authority.

use domain::base::iana::{Class, OptRcode, Rtype};
use domain::base::{Message, Name, ToName};
use domain::rdata::{Ds, Soa};

use super::ParseResponseError;
use crate::dns::dnssec::KeyTag;

/// The DS record set a parent-zone server holds for a child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRecordSet {
    /// Child DS records, deduplicated and sorted by key tag then RDATA.
    pub records: Vec<DsRecord>,
    /// Cache TTL of the parent's DS records.
    pub ttl: u32,
}

impl DsRecordSet {
    /// Key tags of the keys the records name, ascending and deduplicated.
    pub fn key_tags(&self) -> Vec<KeyTag> {
        let mut key_tags: Vec<KeyTag> = self.records.iter().map(|record| record.key_tag).collect();
        key_tags.dedup();
        key_tags
    }
}

/// One DS record of a parent's answer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DsRecord {
    pub key_tag: KeyTag,
    pub digest_type: u8,
    /// Complete DS RDATA (RFC 4034, Section 5.1); key tags alone are ambiguous.
    pub rdata: Vec<u8>,
}

/// Read an authoritative DS answer, or `None` for NODATA/NXDOMAIN.
/// Require AA to avoid stale cached parent data.
pub fn extract_ds_record_set(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    response: &[u8],
) -> Result<Option<DsRecordSet>, ParseResponseError> {
    use domain::base::rdata::ComposeRecordData;

    let message = super::parse_authoritative_response(query_id, qname, Rtype::DS, response)?;

    match super::response_rcode(&message)? {
        OptRcode::NOERROR => {}
        OptRcode::NXDOMAIN => return validate_parent_soa(&message, qname).map(|_| None),
        rcode => return Err(ParseResponseError::Rcode(rcode)),
    }

    let answer = message
        .answer()
        .map_err(|error| ParseResponseError::MalformedAnswer(Box::new(error)))?;
    let mut records = Vec::new();
    let mut ttl: Option<u32> = None;

    for record in answer.limit_to::<Ds<_>>() {
        let record =
            record.map_err(|error| ParseResponseError::MalformedAnswerRecord(Box::new(error)))?;

        // Only DS records at the child's own name are its delegation.
        if !record.owner().name_eq(qname) {
            continue;
        }

        // RFC 2181, Section 5: another class is a different record set.
        if record.class() != Class::IN {
            return Err(ParseResponseError::ForeignClass {
                class: record.class(),
                owner: record.owner().to_string(),
            });
        }

        let mut rdata = Vec::new();
        let Ok(()) = record.data().compose_rdata(&mut rdata);
        records.push(DsRecord {
            key_tag: KeyTag::from(record.data().key_tag()),
            digest_type: record.data().digest_type().to_int(),
            rdata,
        });
        ttl = Some(ttl.map_or(record.ttl().as_secs(), |minimum_ttl| {
            minimum_ttl.min(record.ttl().as_secs())
        }));
    }

    let Some(ttl) = ttl else {
        return validate_parent_soa(&message, qname).map(|_| None);
    };
    records.sort();
    records.dedup();

    Ok(Some(DsRecordSet { records, ttl }))
}

/// Require a strict ancestor's SOA for negative DS answers, NXDOMAIN and NODATA
/// alike: stricter than RFC 2308, Sections 2.1 and 2.2, so the child's own
/// NODATA cannot pass.
fn validate_parent_soa(
    message: &Message<&[u8]>,
    qname: &Name<Vec<u8>>,
) -> Result<(), ParseResponseError> {
    let authority = message
        .authority()
        .map_err(|error| ParseResponseError::MalformedAuthority(Box::new(error)))?;

    for record in authority.limit_to::<Soa<_>>() {
        let record = record
            .map_err(|error| ParseResponseError::MalformedAuthorityRecord(Box::new(error)))?;

        if qname.ends_with(record.owner()) && !qname.name_eq(record.owner()) {
            if record.class() != Class::IN {
                return Err(ParseResponseError::ForeignClass {
                    class: record.class(),
                    owner: record.owner().to_string(),
                });
            }

            return Ok(());
        }
    }

    Err(ParseResponseError::NoParentSoa)
}
