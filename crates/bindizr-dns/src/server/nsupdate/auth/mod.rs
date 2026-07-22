use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};

use super::{
    parser::TsigRecord,
    update::{TsigErrorResponse, UpdateError},
};
use crate::{
    model::tsig_key::{TsigAlgorithm, TsigKey},
    protocol::{TSIG_ERROR_BADKEY, TSIG_ERROR_BADSIG, TSIG_ERROR_BADTIME},
};

/// NOTAUTH/BADKEY error for a TSIG record naming a key bindizr does not hold.
pub(super) fn unknown_key_error(tsig: &TsigRecord) -> UpdateError {
    tsig_notauth(
        format!("unknown TSIG key: {}", tsig.name),
        tsig,
        TSIG_ERROR_BADKEY,
        tsig.time_signed,
        Vec::new(),
    )
}

/// Verify a TSIG-signed nsupdate request against the key it names (RFC 8945).
/// The key was already resolved from the TSIG record's key name; this checks
/// the algorithm, the MAC over the unsigned message, and the signing time.
pub(super) fn validate_tsig(
    tsig: &TsigRecord,
    query_data: &[u8],
    key: &TsigKey,
) -> Result<(), UpdateError> {
    match tsig.algorithm.parse::<TsigAlgorithm>() {
        Ok(algorithm) if algorithm == key.algorithm => {}
        _ => {
            return Err(tsig_notauth(
                format!(
                    "TSIG algorithm '{}' does not match key '{}' ({})",
                    tsig.algorithm, key.name, key.algorithm
                ),
                tsig,
                TSIG_ERROR_BADKEY,
                tsig.time_signed,
                Vec::new(),
            ));
        }
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

    let key_bytes = decode_tsig_secret(&key.secret)?;
    let signed_data = build_tsig_signed_data(query_data, tsig)?;

    verify_mac(key.algorithm, &key_bytes, &signed_data, &tsig.mac).map_err(|e| match e {
        MacError::InvalidKey(msg) => UpdateError::Internal(msg),
        MacError::Mismatch => tsig_notauth(
            "TSIG MAC verification failed".to_string(),
            tsig,
            TSIG_ERROR_BADSIG,
            tsig.time_signed,
            Vec::new(),
        ),
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

enum MacError {
    InvalidKey(String),
    Mismatch,
}

fn verify_mac(
    algorithm: TsigAlgorithm,
    key_bytes: &[u8],
    signed_data: &[u8],
    expected_mac: &[u8],
) -> Result<(), MacError> {
    macro_rules! verify_with {
        ($digest:ty) => {{
            let mut mac = Hmac::<$digest>::new_from_slice(key_bytes)
                .map_err(|e| MacError::InvalidKey(format!("invalid TSIG key: {}", e)))?;
            mac.update(signed_data);
            mac.verify_slice(expected_mac)
                .map_err(|_| MacError::Mismatch)
        }};
    }

    match algorithm {
        TsigAlgorithm::HmacSha256 => verify_with!(Sha256),
        TsigAlgorithm::HmacSha384 => verify_with!(Sha384),
        TsigAlgorithm::HmacSha512 => verify_with!(Sha512),
    }
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
            UpdateError::Internal(format!("stored TSIG secret is not valid base64: {}", e))
        })?;

    if bytes.is_empty() {
        return Err(UpdateError::Internal(
            "stored TSIG secret decodes to an empty key".to_string(),
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

#[cfg(test)]
mod tests;
