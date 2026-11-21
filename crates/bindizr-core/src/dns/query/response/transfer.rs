//! Decode AXFR answer records with the transfer's question and flag rules.

use domain::base::iana::{Class, Opcode, OptRcode, Rtype};
use domain::base::rdata::ComposeRecordData;
use domain::rdata::AllRecordData;

use crate::dns::Ttl;
use crate::dns::name::WireName;
use crate::dns::query::response;
use crate::dns::query::response::ParseResponseError;
use crate::dns::record::Rdata;

/// One answer record with uncompressed RDATA preserving received case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRecord {
    /// Owner name as an absolute presentation name (trailing dot).
    pub name: String,
    pub rtype: Rtype,
    pub ttl: Ttl,
    pub rdata: Rdata,
}

/// Collect an AXFR answer batch; the caller handles SOA delimiters (RFC 5936, Section 2.2).
/// Require the initial echoed question; ignore AA/TC (RFC 5936, Sections 2 and 2.2.1).
pub fn extract_transfer_records(
    query_id: u16,
    qname: &WireName,
    position: TransferMessagePosition,
    response: &[u8],
) -> Result<Vec<TransferRecord>, ParseResponseError> {
    let message = response::parse_response_header(query_id, Opcode::QUERY, response)?;

    if position == TransferMessagePosition::First || message.header_counts().qdcount() != 0 {
        response::validate_question(&message, qname, Rtype::AXFR)?;
    }

    let rcode = response::response_rcode(&message)?;

    if rcode != OptRcode::NOERROR {
        return Err(ParseResponseError::Rcode { rcode });
    }

    let answer = message
        .answer()
        .map_err(|error| ParseResponseError::MalformedAnswer(Box::new(error)))?;
    let mut records = Vec::new();

    for record in answer.limit_to::<AllRecordData<_, _>>() {
        let record =
            record.map_err(|error| ParseResponseError::MalformedAnswerRecord(Box::new(error)))?;

        // Reject foreign classes before the import parser renders them as IN.
        if record.class() != Class::IN {
            return Err(ParseResponseError::ForeignClass {
                class: record.class(),
                owner: record.owner().to_string(),
            });
        }

        let mut rdata = Vec::new();
        let Ok(()) = record.data().compose_rdata(&mut rdata);
        records.push(TransferRecord {
            // Keep the root dot so import cannot re-qualify this absolute name.
            name: format!("{}.", record.owner()),
            rtype: record.rtype(),
            ttl: Ttl::from(record.ttl()),
            rdata: Rdata::new(rdata)?,
        });
    }

    Ok(records)
}

/// A transfer message's position determines which header checks apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMessagePosition {
    First,
    Following,
}
