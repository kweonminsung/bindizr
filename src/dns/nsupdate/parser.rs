use std::fmt;

const DNS_HEADER_LEN: usize = 12;
const CLASS_IN: u16 = 1;

#[derive(Debug, Clone)]
pub struct UpdateRequest {
    pub zone_name: String,
    pub updates: Vec<UpdateRecord>,
}

#[derive(Debug, Clone)]
pub struct UpdateRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    InvalidOpcode,
    InvalidHeader,
    InvalidZoneSection,
    InvalidName,
    InvalidRr,
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

    let _ztype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let zclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    pos += 4;

    if zclass != CLASS_IN {
        return Err(ParseError::InvalidZoneSection);
    }

    for _ in 0..ancount {
        pos = skip_rr(data, pos)?;
    }

    let mut updates = Vec::with_capacity(nscount);
    for _ in 0..nscount {
        let (rr, next) = parse_rr(data, pos)?;
        updates.push(rr);
        pos = next;
    }

    for _ in 0..arcount {
        pos = skip_rr(data, pos)?;
    }

    Ok(UpdateRequest { zone_name, updates })
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
        },
        rdata_end,
    ))
}

fn skip_rr(data: &[u8], pos: usize) -> Result<usize, ParseError> {
    let (_name, name_len) = decode_name(data, pos)?;
    let hdr = pos + name_len;

    if hdr + 10 > data.len() {
        return Err(ParseError::InvalidRr);
    }

    let rdlen = u16::from_be_bytes([data[hdr + 8], data[hdr + 9]]) as usize;
    let next = hdr + 10 + rdlen;

    if next > data.len() {
        return Err(ParseError::InvalidRr);
    }

    Ok(next)
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

pub fn decode_name_from_rdata(rdata: &[u8]) -> Result<String, ParseError> {
    let (name, consumed) = decode_name(rdata, 0)?;
    if consumed != rdata.len() {
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
