use base64::{engine::general_purpose, Engine};
use byteorder::{BigEndian, ReadBytesExt};
use hmac::Mac;
use indexmap::IndexMap;
use std::io::{Cursor, Read};

use super::HmacSha256;

// Message types
const MSGTYPE_STRING: u8 = 0;
const MSGTYPE_BINARYDATA: u8 = 1;
const MSGTYPE_LIST: u8 = 3;
const MSGTYPE_TABLE: u8 = 2;

const ISCCC_ALG_HMAC_SHA256: u8 = 163;

#[derive(Clone, Debug)]
pub enum RNDCValue {
    Binary(Vec<u8>),
    Table(IndexMap<String, RNDCValue>),
    List(Vec<RNDCValue>),
}

#[derive(Debug, Clone)]
pub enum RNDCPayload {
    String(String),
    Binary(Vec<u8>),
    Table(IndexMap<String, RNDCPayload>),
    List(Vec<RNDCPayload>),
}

fn binary_fromwire(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<RNDCPayload, String> {
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;

    match String::from_utf8(buf.clone()) {
        Ok(s) => Ok(RNDCPayload::String(s)),
        Err(_) => Ok(RNDCPayload::Binary(buf)),
    }
}

fn key_fromwire(cursor: &mut Cursor<&[u8]>) -> Result<String, String> {
    let len = cursor.read_u8().map_err(|e| e.to_string())? as usize;
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    String::from_utf8(buf).map_err(|e| e.to_string())
}

fn value_fromwire(cursor: &mut Cursor<&[u8]>) -> Result<RNDCPayload, String> {
    let typ = cursor.read_u8().map_err(|e| e.to_string())?;
    let len = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())? as usize;
    let pos = cursor.position() as usize;

    let slice = &cursor.get_ref()[pos..pos + len];
    let mut sub_cursor = Cursor::new(slice);

    let result = match typ {
        MSGTYPE_STRING | MSGTYPE_BINARYDATA => binary_fromwire(&mut sub_cursor, len),
        MSGTYPE_TABLE => table_fromwire(&mut sub_cursor).map(RNDCPayload::Table),
        MSGTYPE_LIST => list_fromwire(&mut sub_cursor).map(RNDCPayload::List),
        _ => Err(format!("Unknown RNDC message type: {}", typ)),
    };

    cursor.set_position((pos + len) as u64);
    result
}

fn table_fromwire(cursor: &mut Cursor<&[u8]>) -> Result<IndexMap<String, RNDCPayload>, String> {
    let mut map = IndexMap::new();
    while (cursor.position() as usize) < cursor.get_ref().len() {
        let key = key_fromwire(cursor)?;
        let value = value_fromwire(cursor)?;
        map.insert(key, value);
    }
    Ok(map)
}

fn list_fromwire(cursor: &mut Cursor<&[u8]>) -> Result<Vec<RNDCPayload>, String> {
    let mut list = Vec::new();
    while (cursor.position() as usize) < cursor.get_ref().len() {
        let value = value_fromwire(cursor)?;
        list.push(value);
    }
    Ok(list)
}

fn raw_towire(type_byte: u8, buffer: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + buffer.len());
    buf.push(type_byte);
    buf.extend_from_slice(&(buffer.len() as u32).to_be_bytes());
    buf.extend_from_slice(buffer);
    buf
}

fn binary_towire(val: &[u8]) -> Vec<u8> {
    raw_towire(MSGTYPE_BINARYDATA, val)
}

fn list_towire(vals: &[RNDCValue]) -> Vec<u8> {
    let mut bufs = Vec::new();
    for v in vals {
        bufs.extend(value_towire(v));
    }
    raw_towire(MSGTYPE_LIST, &bufs)
}

fn key_towire(key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut buf = Vec::with_capacity(1 + key_bytes.len());
    buf.push(key_bytes.len() as u8);
    buf.extend_from_slice(key_bytes);
    buf
}

fn value_towire(val: &RNDCValue) -> Vec<u8> {
    match val {
        RNDCValue::List(list) => list_towire(list),
        RNDCValue::Table(map) => table_towire(map, false),
        RNDCValue::Binary(data) => binary_towire(data),
    }
}

fn table_towire(val: &IndexMap<String, RNDCValue>, no_header: bool) -> Vec<u8> {
    let mut bufs = Vec::new();
    for (key, value) in val.iter() {
        bufs.extend(key_towire(key));
        bufs.extend(value_towire(value));
    }
    if no_header {
        bufs
    } else {
        raw_towire(MSGTYPE_TABLE, &bufs)
    }
}

pub fn make_signature(secret: &[u8], message_body: &IndexMap<String, RNDCValue>) -> RNDCValue {
    let databuf = table_towire(message_body, true);

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(&databuf);
    let digest = mac.finalize().into_bytes();

    let sig_b64 = general_purpose::STANDARD.encode(&digest);

    let mut sig_buf = vec![0u8; 89];
    sig_buf[0] = ISCCC_ALG_HMAC_SHA256; // 163
    sig_buf[1..(1 + sig_b64.len())].copy_from_slice(sig_b64.as_bytes());

    // _auth: { hsha: sig_buf }
    let mut hsha_map = IndexMap::new();
    hsha_map.insert("hsha".to_string(), RNDCValue::Binary(sig_buf));

    RNDCValue::Table(hsha_map)
}

pub fn encode(obj: &mut IndexMap<String, RNDCValue>, secret: &[u8]) -> Vec<u8> {
    obj.shift_remove("_auth");

    let databuf = table_towire(obj, true);

    let sig_value = make_signature(secret, obj);

    let mut sig_map = IndexMap::new();
    sig_map.insert("_auth".to_string(), sig_value);
    let sigbuf = table_towire(&sig_map, true);

    let length = 8 + sigbuf.len() + databuf.len();
    let mut res = Vec::with_capacity(length);

    res.extend(&(length as u32 - 4).to_be_bytes());
    res.extend(&1u32.to_be_bytes());

    res.extend(&sigbuf);
    res.extend(&databuf);

    res
}

pub fn decode(buf: &[u8]) -> Result<IndexMap<String, RNDCPayload>, String> {
    let mut cursor = Cursor::new(buf);

    let len = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())? as usize;
    if len != buf.len() - 4 {
        return Err("RNDC buffer length mismatch".to_string());
    }

    let version = cursor.read_u32::<BigEndian>().map_err(|e| e.to_string())?;
    if version != 1 {
        return Err(format!("Unknown RNDC protocol version: {}", version));
    }

    let res = table_fromwire(&mut cursor)?;

    Ok(res)
}
