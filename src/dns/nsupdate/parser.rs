use std::fmt;

const DNS_HEADER_LEN: usize = 12;
const CLASS_IN: u16 = 1;
const CLASS_ANY: u16 = 255;
const TYPE_SOA: u16 = 6;
const TSIG_TYPE: u16 = 250;

#[derive(Debug, Clone)]
pub struct UpdateRequest {
    pub zone_name: String,
    pub prerequisites: Vec<PrerequisiteRecord>,
    pub updates: Vec<UpdateRecord>,
    pub tsig: Option<TsigRecord>,
}

#[derive(Debug, Clone)]
pub struct PrerequisiteRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub rdata_start: usize,
}

#[derive(Debug, Clone)]
pub struct UpdateRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub rdata_start: usize,
}

#[derive(Debug, Clone)]
pub struct TsigRecord {
    pub name: String,
    pub algorithm: String,
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: Vec<u8>,
    pub original_id: u16,
    pub error: u16,
    pub other_data: Vec<u8>,
    pub rr_start: usize,
    pub rr_end: usize,
}

#[derive(Debug)]
pub enum ParseError {
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

pub fn parse_update_request(data: &[u8]) -> Result<UpdateRequest, ParseError> {
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

    if ztype != TYPE_SOA || zclass != CLASS_IN {
        return Err(ParseError::InvalidZoneSection);
    }

    let mut prerequisites = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (rr, next) = parse_rr(data, pos)?;
        prerequisites.push(PrerequisiteRecord {
            name: rr.name,
            rr_type: rr.rr_type,
            class: rr.class,
            ttl: rr.ttl,
            rdata: rr.rdata,
            rdata_start: rr.rdata_start,
        });
        pos = next;
    }

    let mut updates = Vec::with_capacity(nscount);
    for _ in 0..nscount {
        let (rr, next) = parse_rr(data, pos)?;
        updates.push(rr);
        pos = next;
    }

    let tsig = match arcount {
        0 => None,
        1 => {
            let (record, next) = parse_tsig_rr(data, pos)?;
            pos = next;
            Some(record)
        }
        _ => return Err(ParseError::InvalidHeader),
    };

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

fn parse_tsig_rr(data: &[u8], pos: usize) -> Result<(TsigRecord, usize), ParseError> {
    let rr_start = pos;
    let (name, name_len) = decode_name(data, pos)?;
    let hdr = pos + name_len;

    if hdr + 10 > data.len() {
        return Err(ParseError::InvalidTsig);
    }

    let rr_type = u16::from_be_bytes([data[hdr], data[hdr + 1]]);
    let class = u16::from_be_bytes([data[hdr + 2], data[hdr + 3]]);
    let ttl = u32::from_be_bytes([data[hdr + 4], data[hdr + 5], data[hdr + 6], data[hdr + 7]]);
    let rdlen = u16::from_be_bytes([data[hdr + 8], data[hdr + 9]]) as usize;

    if rr_type != TSIG_TYPE || class != CLASS_ANY || ttl != 0 {
        return Err(ParseError::InvalidTsig);
    }

    let rdata_start = hdr + 10;
    let rdata_end = rdata_start + rdlen;
    if rdata_end > data.len() {
        return Err(ParseError::InvalidTsig);
    }

    let mut p = rdata_start;
    let (algorithm, algo_len) = decode_name(data, p).map_err(|_| ParseError::InvalidTsig)?;
    p += algo_len;

    if p + 6 + 2 + 2 > rdata_end {
        return Err(ParseError::InvalidTsig);
    }

    let time_signed = ((data[p] as u64) << 40)
        | ((data[p + 1] as u64) << 32)
        | ((data[p + 2] as u64) << 24)
        | ((data[p + 3] as u64) << 16)
        | ((data[p + 4] as u64) << 8)
        | data[p + 5] as u64;
    p += 6;

    let fudge = u16::from_be_bytes([data[p], data[p + 1]]);
    p += 2;

    let mac_size = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
    p += 2;

    if p + mac_size + 2 + 2 + 2 > rdata_end {
        return Err(ParseError::InvalidTsig);
    }

    let mac = data[p..p + mac_size].to_vec();
    p += mac_size;

    let original_id = u16::from_be_bytes([data[p], data[p + 1]]);
    p += 2;

    let error = u16::from_be_bytes([data[p], data[p + 1]]);
    p += 2;

    let other_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
    p += 2;

    if p + other_len != rdata_end {
        return Err(ParseError::InvalidTsig);
    }

    let other_data = data[p..p + other_len].to_vec();

    Ok((
        TsigRecord {
            name,
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other_data,
            rr_start,
            rr_end: rdata_end,
        },
        rdata_end,
    ))
}

fn decode_name(data: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    if start >= data.len() {
        return Err(ParseError::InvalidName);
    }

    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut consumed = 0usize;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if pos >= data.len() {
            return Err(ParseError::InvalidName);
        }

        let len = data[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return Err(ParseError::InvalidName);
            }

            let ptr = (((len as u16 & 0x3F) << 8) | data[pos + 1] as u16) as usize;
            if ptr >= data.len() {
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

        if label_end > data.len() || label_len > 63 {
            return Err(ParseError::InvalidName);
        }

        let label = std::str::from_utf8(&data[label_start..label_end])
            .map_err(|_| ParseError::InvalidName)?;
        labels.push(label.to_string());

        if !jumped {
            consumed += 1 + label_len;
            pos = label_end;
        } else {
            pos = label_end;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    };

    Ok((name, consumed))
}

pub fn decode_name_from_rdata(
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

pub fn decode_txt_from_rdata(rdata: &[u8]) -> Result<String, ParseError> {
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
mod tests {
    use super::{ParseError, decode_name_from_rdata, parse_update_request};

    fn minimal_update_with_ztype(ztype: u16) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&[
            0x12, 0x34, // ID
            0x28, 0x00, // Opcode UPDATE
            0x00, 0x01, // ZOCOUNT
            0x00, 0x00, // PRCOUNT
            0x00, 0x00, // UPCOUNT
            0x00, 0x00, // ADCOUNT
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ]);
        message.extend_from_slice(&ztype.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message
    }

    #[test]
    fn decode_name_from_rdata_handles_compression_pointer() {
        let mut message = Vec::new();
        message.extend_from_slice(&[
            3, b'w', b'w', b'w', 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0,
        ]);

        let target_offset = 5usize;
        let rdata_start = message.len();
        let ptr_hi = 0xC0 | ((target_offset >> 8) as u8 & 0x3F);
        let ptr_lo = (target_offset & 0xFF) as u8;
        message.extend_from_slice(&[ptr_hi, ptr_lo]);

        let decoded = decode_name_from_rdata(&message, rdata_start, 2).unwrap();
        assert_eq!(decoded, "example.com.");
    }

    #[test]
    fn decode_name_from_rdata_rejects_trailing_bytes() {
        let message = [1, b'a', 0, 0];
        let err = decode_name_from_rdata(&message, 0, message.len()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidName));
    }

    #[test]
    fn parse_update_request_rejects_non_soa_zone_type() {
        let message = minimal_update_with_ztype(1);
        let err = parse_update_request(&message).unwrap_err();
        assert!(matches!(err, ParseError::InvalidZoneSection));
    }

    #[test]
    fn parse_update_request_accepts_soa_zone_type() {
        let message = minimal_update_with_ztype(6);
        let request = parse_update_request(&message).unwrap();
        assert_eq!(request.zone_name, "example.com.");
    }
}
