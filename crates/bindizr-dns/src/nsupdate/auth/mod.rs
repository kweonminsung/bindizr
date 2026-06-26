use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::{
    parser::{TsigRecord, UpdateRequest},
    update::{TsigErrorResponse, UpdateError},
};
use crate::{
    config,
    protocol::{TSIG_ERROR_BADKEY, TSIG_ERROR_BADSIG, TSIG_ERROR_BADTIME},
};

type HmacSha256 = Hmac<Sha256>;

pub(super) fn validate_tsig(
    request: &UpdateRequest,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), UpdateError> {
    let dns_config = &config::get_bindizr_config().dns;
    let expected_key_name = dns_config.nsupdate_tsig_key_name.trim().to_string();
    let secret = dns_config.nsupdate_tsig_key.trim().to_string();

    if expected_key_name.is_empty() || secret.is_empty() {
        return Ok(());
    }

    let tsig = request
        .tsig
        .as_ref()
        .ok_or_else(|| UpdateError::Refused(format!("missing TSIG record from {}", client_addr)))?;

    let expected_key_canonical = encode_canonical_name(&expected_key_name)?;
    if tsig.name_canonical != expected_key_canonical {
        return Err(tsig_notauth(
            format!("unexpected TSIG key name: {}", tsig.name),
            tsig,
            TSIG_ERROR_BADKEY,
            tsig.time_signed,
            Vec::new(),
        ));
    }

    let algorithm = tsig.algorithm.trim_end_matches('.').to_ascii_lowercase();
    if algorithm != "hmac-sha256" && algorithm != "hmac-sha256.sig-alg.reg.int" {
        return Err(tsig_notauth(
            format!("unsupported TSIG algorithm: {}", tsig.algorithm),
            tsig,
            TSIG_ERROR_BADKEY,
            tsig.time_signed,
            Vec::new(),
        ));
    }

    if query_data.len() < 12 {
        return Err(UpdateError::Refused("query is too short".to_string()));
    }

    let expected_id = u16::from_be_bytes([query_data[0], query_data[1]]);
    if tsig.original_id != expected_id {
        return Err(tsig_notauth(
            "TSIG original id mismatch".to_string(),
            tsig,
            TSIG_ERROR_BADSIG,
            tsig.time_signed,
            Vec::new(),
        ));
    }

    let key_bytes = decode_tsig_secret(&secret)?;
    let signed_data = build_tsig_signed_data(query_data, tsig)?;

    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|e| UpdateError::Internal(format!("invalid TSIG key: {}", e)))?;
    mac.update(&signed_data);
    mac.verify_slice(&tsig.mac).map_err(|_| {
        tsig_notauth(
            "TSIG MAC verification failed".to_string(),
            tsig,
            TSIG_ERROR_BADSIG,
            tsig.time_signed,
            Vec::new(),
        )
    })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| UpdateError::Internal(format!("system time error: {}", e)))?
        .as_secs();
    let skew = now.abs_diff(tsig.time_signed);
    if skew > u64::from(tsig.fudge) {
        return Err(tsig_notauth(
            format!("TSIG time skew too large: {}s (fudge={})", skew, tsig.fudge),
            tsig,
            TSIG_ERROR_BADTIME,
            now,
            encode_u48(now),
        ));
    }

    Ok(())
}

fn tsig_notauth(
    msg: String,
    tsig: &TsigRecord,
    error: u16,
    time_signed: u64,
    other_data: Vec<u8>,
) -> UpdateError {
    UpdateError::NotAuth {
        msg,
        tsig: Some(TsigErrorResponse {
            name_canonical: tsig.name_canonical.clone(),
            algorithm_canonical: tsig.algorithm_canonical.clone(),
            original_id: tsig.original_id,
            time_signed,
            fudge: tsig.fudge,
            error,
            other_data,
        }),
    }
}

fn encode_u48(value: u64) -> Vec<u8> {
    vec![
        ((value >> 40) & 0xff) as u8,
        ((value >> 32) & 0xff) as u8,
        ((value >> 24) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ]
}

fn decode_tsig_secret(raw: &str) -> Result<Vec<u8>, UpdateError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| {
            UpdateError::Internal(format!("dns.nsupdate_tsig_key must be valid base64: {}", e))
        })?;

    if bytes.is_empty() {
        return Err(UpdateError::Internal(
            "dns.nsupdate_tsig_key must not decode to an empty key".to_string(),
        ));
    }

    Ok(bytes)
}

fn encode_canonical_name(name: &str) -> Result<Vec<u8>, UpdateError> {
    let mut out = Vec::new();
    crate::xfr::wire::encode_domain_name(&name.to_ascii_lowercase(), &mut out)
        .map_err(|e| UpdateError::Internal(e.to_string()))?;
    Ok(out)
}

fn build_tsig_signed_data(query_data: &[u8], tsig: &TsigRecord) -> Result<Vec<u8>, UpdateError> {
    if query_data.len() < 12
        || tsig.rr_start < 12
        || tsig.rr_end > query_data.len()
        || tsig.rr_start >= tsig.rr_end
    {
        return Err(UpdateError::Refused("invalid TSIG envelope".to_string()));
    }

    let mut message = Vec::with_capacity(query_data.len() - (tsig.rr_end - tsig.rr_start));
    message.extend_from_slice(&query_data[..tsig.rr_start]);
    message.extend_from_slice(&query_data[tsig.rr_end..]);

    let arcount = u16::from_be_bytes([query_data[10], query_data[11]]);
    if arcount == 0 {
        return Err(UpdateError::Refused("TSIG ARCOUNT underflow".to_string()));
    }

    let new_arcount = arcount - 1;
    message[10..12].copy_from_slice(&new_arcount.to_be_bytes());

    let mut out = message;
    out.extend_from_slice(&tsig.name_canonical);
    out.extend_from_slice(&255u16.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&tsig.algorithm_canonical);
    out.push(((tsig.time_signed >> 40) & 0xff) as u8);
    out.push(((tsig.time_signed >> 32) & 0xff) as u8);
    out.push(((tsig.time_signed >> 24) & 0xff) as u8);
    out.push(((tsig.time_signed >> 16) & 0xff) as u8);
    out.push(((tsig.time_signed >> 8) & 0xff) as u8);
    out.push((tsig.time_signed & 0xff) as u8);
    out.extend_from_slice(&tsig.fudge.to_be_bytes());
    out.extend_from_slice(&tsig.error.to_be_bytes());
    out.extend_from_slice(&(tsig.other_data.len() as u16).to_be_bytes());
    out.extend_from_slice(&tsig.other_data);

    Ok(out)
}

#[cfg(test)]
mod tests;
