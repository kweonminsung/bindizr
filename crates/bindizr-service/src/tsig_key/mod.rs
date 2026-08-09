use base64::Engine;
use bindizr_core::dns::name::to_lookup_name;
use chrono::Utc;
use rand::RngExt;

use crate::{
    RepositoryTx,
    authorization::Caller,
    error::ServiceError,
    model::tsig_key::{TsigAlgorithm, TsigKey},
    repository::RepositoryService,
};

/// Byte length of generated secrets; matches `tsig-keygen`'s default for
/// HMAC-SHA256 and is sufficient entropy for the larger algorithms too.
const GENERATED_SECRET_LEN: usize = 32;

/// Creates, lists, and deletes TSIG keys used for nsupdate authentication.
pub struct TsigKeyService;

impl TsigKeyService {
    /// Create a TSIG key. When `secret` is omitted a random one is generated;
    /// when provided it must be valid, non-empty base64 (an imported key).
    /// `is_global` is fixed at creation: a global key may update every zone
    /// without any policy.
    pub async fn create(
        caller: &Caller,
        name: &str,
        algorithm: Option<&str>,
        secret: Option<&str>,
        is_global: bool,
    ) -> Result<TsigKey, ServiceError> {
        caller.require_global("manage TSIG keys and policies")?;

        let name = normalize_key_name(name)?;
        let algorithm = parse_algorithm(algorithm)?;
        let secret = match secret {
            Some(secret) => validate_secret(secret)?,
            None => generate_secret(),
        };

        if RepositoryService::get_tsig_key_by_name(&name)
            .await?
            .is_some()
        {
            return Err(ServiceError::tsig_key_conflict(&name));
        }

        RepositoryService::create_tsig_key(TsigKey {
            id: 0,
            name,
            algorithm,
            secret,
            is_global,
            created_at: Utc::now(),
        })
        .await
    }

    /// List all TSIG keys with their secrets cleared.
    pub async fn list(caller: &Caller) -> Result<Vec<TsigKey>, ServiceError> {
        caller.require_global("manage TSIG keys and policies")?;

        let mut keys = RepositoryService::get_all_tsig_keys().await?;
        for key in &mut keys {
            key.secret.clear();
        }
        Ok(keys)
    }

    /// Fetch one TSIG key by name, including its secret.
    pub async fn get(caller: &Caller, name: &str) -> Result<TsigKey, ServiceError> {
        caller.require_global("manage TSIG keys and policies")?;

        Self::lookup_by_name(name).await
    }

    /// Fetch one TSIG key by name. This is the unchecked lookup for
    /// service-internal use; front ends go through [`Self::get`].
    pub(crate) async fn lookup_by_name(name: &str) -> Result<TsigKey, ServiceError> {
        let name = normalize_key_name(name)?;
        RepositoryService::get_tsig_key_by_name(&name)
            .await?
            .ok_or_else(|| ServiceError::tsig_key_not_found(&name))
    }

    /// Look up a key by (wire) name within the caller's transaction. Used by
    /// the nsupdate path to resolve the key named in an incoming TSIG record.
    pub async fn find_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        name: &str,
    ) -> Result<Option<TsigKey>, ServiceError> {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        RepositoryService::get_tsig_key_by_name_tx(tx, &name).await
    }

    /// Delete a TSIG key by name; refused while any zone TSIG policy uses it.
    pub async fn delete(caller: &Caller, name: &str) -> Result<(), ServiceError> {
        caller.require_global("manage TSIG keys and policies")?;

        let key = Self::lookup_by_name(name).await?;

        let policy_count = RepositoryService::count_zone_tsig_policies_by_key_id(key.id).await?;
        if policy_count > 0 {
            return Err(ServiceError::tsig_key_in_use(&key.name, policy_count));
        }

        RepositoryService::delete_tsig_key(key.id).await
    }
}

/// Normalize a TSIG key name: it travels in the TSIG record's NAME field, so
/// it must be a valid domain name. Stored lowercase without the trailing dot.
pub(crate) fn normalize_key_name(value: &str) -> Result<String, ServiceError> {
    to_lookup_name(value).map_err(|e| ServiceError::invalid_input(format!("TSIG key name {}", e)))
}

fn parse_algorithm(value: Option<&str>) -> Result<TsigAlgorithm, ServiceError> {
    match value {
        None => Ok(TsigAlgorithm::HmacSha256),
        Some(raw) => raw.parse().map_err(ServiceError::invalid_input),
    }
}

/// HMAC security degrades to the key length, so refuse imports under 128 bits.
const MIN_IMPORTED_SECRET_BYTES: usize = 16;
/// The base64 form must fit the `tsig_keys.secret` VARCHAR(255) column.
const MAX_SECRET_BASE64_LEN: usize = 255;

fn validate_secret(value: &str) -> Result<String, ServiceError> {
    let trimmed = value.trim();

    if trimmed.len() > MAX_SECRET_BASE64_LEN {
        return Err(ServiceError::invalid_input(format!(
            "TSIG key secret must be at most {} base64 characters",
            MAX_SECRET_BASE64_LEN
        )));
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| {
            ServiceError::invalid_input(format!("TSIG key secret must be valid base64: {}", e))
        })?;

    if decoded.len() < MIN_IMPORTED_SECRET_BYTES {
        return Err(ServiceError::invalid_input(format!(
            "TSIG key secret must decode to at least {} bytes ({} bits)",
            MIN_IMPORTED_SECRET_BYTES,
            MIN_IMPORTED_SECRET_BYTES * 8
        )));
    }

    Ok(trimmed.to_string())
}

fn generate_secret() -> String {
    let bytes: [u8; GENERATED_SECRET_LEN] = rand::rng().random();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests;
