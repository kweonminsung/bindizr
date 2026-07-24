use std::fmt;

use bindizr_core::dns::name::MAX_DNS_LABEL_LEN;

use crate::{
    model::record::RecordType,
    protocol::{CLASS_ANY, CLASS_IN, DNS_COMPRESSION_POINTER_MASK, DNS_HEADER_LEN, TYPE_TSIG},
};

#[derive(Debug, Clone)]
pub(super) struct UpdateRequest {
    pub zone_name: String,
    pub prerequisites: Vec<UpdateRecord>,
    pub updates: Vec<UpdateRecord>,
    pub tsig: Option<TsigRecord>,
}

/// One RR from the prerequisite or update section.
#[derive(Debug, Clone)]
pub(super) struct UpdateRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub rdata_start: usize,
}

/// The request's TSIG record, reduced to what the update flow needs: the key
/// name for the DB lookup and the fudge echoed in the response. Cryptographic
/// validation re-reads the full record via `domain::tsig`; parsing here still
/// rejects structurally invalid TSIG RRs with FORMERR (RFC 8945 §5.2) before
/// that happens.
#[derive(Debug, Clone)]
pub(super) struct TsigRecord {
    pub name: String,
    pub fudge: u16,
}

#[derive(Debug)]
pub(super) enum ParseError {
    TooShort,
    InvalidOpcode,
    InvalidHeader,
    InvalidZoneSection,
    InvalidName,
    InvalidRr,
    InvalidTsig,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "DNS message is too short"),
            ParseError::InvalidOpcode => write!(f, "Not a DNS UPDATE opcode"),
            ParseError::InvalidHeader => write!(f, "Invalid DNS UPDATE header"),
            ParseError::InvalidZoneSection => write!(f, "Invalid DNS UPDATE zone section"),
            ParseError::InvalidName => write!(f, "Invalid compressed domain name"),
            ParseError::InvalidRr => write!(f, "Invalid resource record in UPDATE section"),
            ParseError::InvalidTsig => write!(f, "Invalid TSIG resource record"),
        }
    }
}

pub(super) fn parse_update_request(data: &[u8]) -> Result<UpdateRequest, ParseError> {
    if data.len() < DNS_HEADER_LEN {
        return Err(ParseError::TooShort);
    }

    let opcode = (data[2] >> 3) & 0x0f;
    if opcode != 5 {
        return Err(ParseError::InvalidOpcode);
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    if qdcount != 1 {
        return Err(ParseError::InvalidHeader);
    }

    let mut pos = DNS_HEADER_LEN;

    let (zone_name, consumed) = decode_name(data, pos)?;
    pos += consumed;

    if pos + 4 > data.len() {
        return Err(ParseError::InvalidZoneSection);
    }

    let ztype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let zclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    pos += 4;

    if ztype != RecordType::SOA.wire_code() || zclass != CLASS_IN {
        return Err(ParseError::InvalidZoneSection);
    }

    let mut prerequisites = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (rr, next) = parse_rr(data, pos)?;
        prerequisites.push(rr);
        pos = next;
    }

    let mut updates = Vec::with_capacity(nscount);
    for _ in 0..nscount {
        let (rr, next) = parse_rr(data, pos)?;
        updates.push(rr);
        pos = next;
    }

    let (tsig, next) = parse_additional_section(data, pos, arcount)?;
    pos = next;

    if pos != data.len() {
        return Err(ParseError::InvalidHeader);
    }

    Ok(UpdateRequest {
        zone_name,
        prerequisites,
        updates,
        tsig,
    })
}

fn parse_rr(data: &[u8], pos: usize) -> Result<(UpdateRecord, usize), ParseError> {
    let (name, name_len) = decode_name(data, pos)?;
    let hdr = pos + name_len;

    if hdr + 10 > data.len() {
        return Err(ParseError::InvalidRr);
    }

    let rr_type = u16::from_be_bytes([data[hdr], data[hdr + 1]]);
    let class = u16::from_be_bytes([data[hdr + 2], data[hdr + 3]]);
    let ttl = u32::from_be_bytes([data[hdr + 4], data[hdr + 5], data[hdr + 6], data[hdr + 7]]);
    let rdlen = u16::from_be_bytes([data[hdr + 8], data[hdr + 9]]) as usize;

    let rdata_start = hdr + 10;
    let rdata_end = rdata_start + rdlen;
    if rdata_end > data.len() {
        return Err(ParseError::InvalidRr);
    }

    Ok((
        UpdateRecord {
            name,
            rr_type,
            class,
            ttl,
            rdata: data[rdata_start..rdata_end].to_vec(),
            rdata_start,
        },
        rdata_end,
    ))
}

fn parse_additional_section(
    data: &[u8],
    mut pos: usize,
    count: usize,
) -> Result<(Option<TsigRecord>, usize), ParseError> {
    let mut tsig = None;

    for index in 0..count {
        let rr_type = peek_rr_type(data, pos)?;
        if rr_type == TYPE_TSIG {
            if tsig.is_some() || index + 1 != count {
                return Err(ParseError::InvalidTsig);
            }

            let (record, next) = parse_tsig_rr(data, pos)?;
            tsig = Some(record);
            pos = next;
        } else {
            let (_, next) = parse_rr(data, pos)?;
            pos = next;
        }
    }

    Ok((tsig, pos))
}

fn peek_rr_type(data: &[u8], pos: usize) -> Result<u16, ParseError> {
    let (_, name_len) = decode_name(data, pos)?;
    let hdr = pos + name_len;

    if hdr + 10 > data.len() {
        return Err(ParseError::InvalidRr);
    }

    Ok(u16::from_be_bytes([data[hdr], data[hdr + 1]]))
}

fn parse_tsig_rr(data: &[u8], pos: usize) -> Result<(TsigRecord, usize), ParseError> {
    let (name, name_len) = decode_name(data, pos)?;
    let hdr = pos + name_len;

    if hdr + 10 > data.len() {
        return Err(ParseError::InvalidTsig);
    }

    let rr_type = u16::from_be_bytes([data[hdr], data[hdr + 1]]);
    let class = u16::from_be_bytes([data[hdr + 2], data[hdr + 3]]);
    let ttl = u32::from_be_bytes([data[hdr + 4], data[hdr + 5], data[hdr + 6], data[hdr + 7]]);
    let rdlen = u16::from_be_bytes([data[hdr + 8], data[hdr + 9]]) as usize;

    if rr_type != TYPE_TSIG || class != CLASS_ANY || ttl != 0 {
        return Err(ParseError::InvalidTsig);
    }

    let rdata_start = hdr + 10;
    let rdata_end = rdata_start + rdlen;
    if rdata_end > data.len() {
        return Err(ParseError::InvalidTsig);
    }

    let mut p = rdata_start;
    let (_, algo_len) = decode_name(data, p).map_err(|_| ParseError::InvalidTsig)?;
    p += algo_len;

    if p + 6 + 2 + 2 > rdata_end {
        return Err(ParseError::InvalidTsig);
    }

    p += 6; // Time signed

    let fudge = u16::from_be_bytes([data[p], data[p + 1]]);
    p += 2;

    let mac_size = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
    p += 2;

    if p + mac_size + 2 + 2 + 2 > rdata_end {
        return Err(ParseError::InvalidTsig);
    }

    p += mac_size + 2 + 2; // MAC, original ID, error

    let other_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
    p += 2;

    if p + other_len != rdata_end {
        return Err(ParseError::InvalidTsig);
    }

    Ok((TsigRecord { name, fudge }, rdata_end))
}

/// Walks a (possibly compressed) wire-format name at `start`, calling
/// `on_label` with each raw label, and returns the octets consumed at `start`
/// (a compression pointer consumes 2 regardless of where it points).
fn walk_name(
    data: &[u8],
    start: usize,
    mut on_label: impl FnMut(&[u8]) -> Result<(), ParseError>,
) -> Result<usize, ParseError> {
    if start >= data.len() {
        return Err(ParseError::InvalidName);
    }

    let mut pos = start;
    let mut consumed = 0usize;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if pos >= data.len() {
            return Err(ParseError::InvalidName);
        }

        let len = data[pos];
        if len & DNS_COMPRESSION_POINTER_MASK == DNS_COMPRESSION_POINTER_MASK {
            if pos + 1 >= data.len() {
                return Err(ParseError::InvalidName);
            }

            let ptr = (((len as u16 & 0x3F) << 8) | data[pos + 1] as u16) as usize;
            if ptr >= pos {
                return Err(ParseError::InvalidName);
            }

            if !jumped {
                consumed += 2;
                jumped = true;
            }

            pos = ptr;
            jumps += 1;
            if jumps > data.len() {
                return Err(ParseError::InvalidName);
            }
            continue;
        }

        if len == 0 {
            if !jumped {
                consumed += 1;
            }
            break;
        }

        let label_len = len as usize;
        let label_start = pos + 1;
        let label_end = label_start + label_len;

        if label_end > data.len() || label_len > MAX_DNS_LABEL_LEN {
            return Err(ParseError::InvalidName);
        }

        on_label(&data[label_start..label_end])?;

        if !jumped {
            consumed += 1 + label_len;
        }
        pos = label_end;
    }

    Ok(consumed)
}

/// Decodes a name into dotted presentation form with a trailing dot.
fn decode_name(data: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut labels: Vec<String> = Vec::new();
    let consumed = walk_name(data, start, |label| {
        let label = std::str::from_utf8(label).map_err(|_| ParseError::InvalidName)?;
        labels.push(label.to_string());
        Ok(())
    })?;

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    };

    Ok((name, consumed))
}

pub(super) fn decode_name_from_rdata(
    message: &[u8],
    rdata_start: usize,
    rdata_len: usize,
) -> Result<String, ParseError> {
    if rdata_start + rdata_len > message.len() {
        return Err(ParseError::InvalidName);
    }

    let (name, consumed) = decode_name(message, rdata_start)?;
    if consumed != rdata_len {
        return Err(ParseError::InvalidName);
    }
    Ok(name)
}

pub(super) fn decode_txt_from_rdata(rdata: &[u8]) -> Result<String, ParseError> {
    let mut pos = 0usize;
    let mut out = String::new();

    while pos < rdata.len() {
        let chunk_len = rdata[pos] as usize;
        pos += 1;

        if pos + chunk_len > rdata.len() {
            return Err(ParseError::InvalidRr);
        }

        let chunk =
            std::str::from_utf8(&rdata[pos..pos + chunk_len]).map_err(|_| ParseError::InvalidRr)?;
        out.push_str(chunk);
        pos += chunk_len;
    }

    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests;
