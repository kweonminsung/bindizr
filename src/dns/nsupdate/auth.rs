use super::{
    parser::{TsigRecord, UpdateRequest},
    update::UpdateError,
};
use crate::config;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

type HmacSha256 = Hmac<Sha256>;

pub(super) fn validate_tsig(
    request: &UpdateRequest,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<(), UpdateError> {
    let secret = config::get_config_optional::<String>("dns.nsupdate_tsig_key")
        .unwrap_or_default()
        .trim()
        .to_string();

    if secret.is_empty() {
        return Ok(());
    }

    let tsig = request
        .tsig
        .as_ref()
        .ok_or_else(|| UpdateError::Refused(format!("missing TSIG record from {}", client_addr)))?;

    let algorithm = tsig.algorithm.trim_end_matches('.').to_ascii_lowercase();
    if algorithm != "hmac-sha256" && algorithm != "hmac-sha256.sig-alg.reg.int" {
        return Err(UpdateError::Refused(format!(
            "unsupported TSIG algorithm: {}",
            tsig.algorithm
        )));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| UpdateError::Internal(format!("system time error: {}", e)))?
        .as_secs();
    let skew = now.abs_diff(tsig.time_signed);
    if skew > u64::from(tsig.fudge) {
        return Err(UpdateError::Refused(format!(
            "TSIG time skew too large: {}s (fudge={})",
            skew, tsig.fudge
        )));
    }

    if query_data.len() < 12 {
        return Err(UpdateError::Refused("query is too short".to_string()));
    }

    let expected_id = u16::from_be_bytes([query_data[0], query_data[1]]);
    if tsig.original_id != expected_id {
        return Err(UpdateError::Refused(
            "TSIG original id mismatch".to_string(),
        ));
    }

    let key_bytes = decode_tsig_secret(&secret)?;
    let signed_data = build_tsig_signed_data(query_data, tsig)?;

    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|e| UpdateError::Internal(format!("invalid TSIG key: {}", e)))?;
    mac.update(&signed_data);
    mac.verify_slice(&tsig.mac)
        .map_err(|_| UpdateError::Refused("TSIG MAC verification failed".to_string()))?;

    Ok(())
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
