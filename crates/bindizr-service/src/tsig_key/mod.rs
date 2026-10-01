//! Manages TSIG credentials shared by update and transfer authentication.

use base64::Engine;
use bindizr_core::{dns::name::parse_lookup_name, model::tsig_key::TsigKeyId};
use chrono::Utc;
use rand::RngExt;

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    model::tsig_key::{TsigAlgorithm, TsigKey},
    pagination::build_page,
    text::MAX_COLUMN_TEXT_LEN,
    types::{CreateTsigKeyRequest, GetTsigKeyResponse, PageRequest, PaginatedResponse},
};

/// Byte length of generated secrets; matches `tsig-keygen`'s default for
/// HMAC-SHA256 and is sufficient entropy for the larger algorithms too.
const GENERATED_SECRET_LEN: usize = 32;

/// Create a TSIG key. When `secret` is omitted a random one is generated;
/// when provided it must be valid, non-empty base64 (an imported key).
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateTsigKeyRequest,
) -> Result<TsigKey, ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    let name = normalize_key_name(&request.name)?;
    let algorithm = request
        .algorithm
        .as_deref()
        .map(str::parse::<TsigAlgorithm>)
        .transpose()
        .map_err(ServiceError::invalid_input)?
        .unwrap_or_default();
    let secret = match request.secret.as_deref() {
        Some(secret) => normalize_secret(secret)?,
        None => generate_secret(),
    };

    // Friendly pre-check; the UNIQUE(name) backstop covers the race.
    if bindizr_db::tsig_key::get_by_name(cx.db(), &name)
        .await?
        .is_some()
    {
        return Err(ServiceError::tsig_key_conflict(&name));
    }

    bindizr_db::tsig_key::create(
        cx.db(),
        TsigKey {
            id: TsigKeyId::UNWRITTEN,
            name: name.clone(),
            algorithm,
            secret,
            is_global: request.global,
            created_at: Utc::now(),
        },
    )
    .await
    .map_err(|e| {
        // A create that raced past the pre-check trips UNIQUE(name); the
        // backstop reads as the same conflict.
        if e.is_unique_violation() {
            ServiceError::tsig_key_conflict(&name)
        } else {
            e.into()
        }
    })
}

/// List all TSIG keys.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    page: PageRequest,
) -> Result<PaginatedResponse<GetTsigKeyResponse>, ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    let keys = bindizr_db::tsig_key::list_all(cx.db()).await?;
    build_page(
        keys.iter().map(GetTsigKeyResponse::from).collect(),
        page.limit,
        page.offset,
    )
}

/// Fetch one TSIG key by name, including its secret.
pub async fn get(cx: &Context, caller: &Caller, name: &str) -> Result<TsigKey, ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    lookup_by_name(cx, name).await
}

/// Fetch one TSIG key by name. This is the unchecked lookup for
/// service-internal use; front ends go through [`get`].
pub(crate) async fn lookup_by_name(cx: &Context, name: &str) -> Result<TsigKey, ServiceError> {
    let name = normalize_key_name(name)?;
    bindizr_db::tsig_key::get_by_name(cx.db(), &name)
        .await?
        .ok_or_else(|| ServiceError::tsig_key_not_found(&name))
}

/// Look up the key an incoming TSIG record names. Authentication precedes
/// any zone transaction, so this is a plain read.
pub async fn find_by_wire_name(cx: &Context, name: &str) -> Result<Option<TsigKey>, ServiceError> {
    // Canonicalize like storage does; an unparseable name matches no key.
    let Ok(name) = normalize_key_name(name) else {
        return Ok(None);
    };
    Ok(bindizr_db::tsig_key::get_by_name(cx.db(), &name).await?)
}

/// Delete a TSIG key by name; refused while it still holds grants or
/// signs a secondary's NOTIFY.
pub async fn delete(cx: &Context, caller: &Caller, name: &str) -> Result<(), ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    let key = lookup_by_name(cx, name).await?;

    let grant_count = bindizr_db::tsig_grant::count_by_key_id(cx.db(), key.id).await?;
    if grant_count > 0 {
        return Err(ServiceError::tsig_key_in_use(&key.name, grant_count));
    }
    let secondary_count =
        bindizr_db::secondary::count_by_notify_tsig_key_id(cx.db(), key.id).await?;
    if secondary_count > 0 {
        return Err(ServiceError::TsigKeyInUse(format!(
            "TSIG key '{}' still signs NOTIFY for {} secondar{}",
            key.name,
            secondary_count,
            if secondary_count == 1 { "y" } else { "ies" }
        )));
    }

    bindizr_db::tsig_key::delete(cx.db(), key.id)
        .await
        .map_err(|e| {
            // A grant or secondary that took the key between the counts above and
            // this delete trips the FK: the same in-use conflict.
            if e.is_foreign_key_violation() {
                ServiceError::TsigKeyInUse(
                    "TSIG key is still referenced by zone TSIG grants or secondaries".to_string(),
                )
            } else {
                e.into()
            }
        })
}

/// Normalize a TSIG key name: it travels in the TSIG record's NAME field, so
/// it must be a valid domain name. Stored lowercase without the trailing dot.
pub(crate) fn normalize_key_name(value: &str) -> Result<String, ServiceError> {
    let name = parse_lookup_name(value)
        .map_err(|e| ServiceError::invalid_input(format!("TSIG key name {}", e)))?;
    if name.len() > MAX_COLUMN_TEXT_LEN {
        return Err(ServiceError::invalid_input(format!(
            "TSIG key name must be {} characters or fewer in its canonical spelling",
            MAX_COLUMN_TEXT_LEN
        )));
    }
    Ok(name)
}

/// HMAC security degrades to the key length, so refuse imports under 128 bits.
const MIN_IMPORTED_SECRET_BYTES: usize = 16;

/// Validate and normalize a base64-encoded TSIG secret.
fn normalize_secret(value: &str) -> Result<String, ServiceError> {
    let trimmed = value.trim();

    if trimmed.len() > MAX_COLUMN_TEXT_LEN {
        return Err(ServiceError::invalid_input(format!(
            "TSIG key secret must be at most {} base64 characters",
            MAX_COLUMN_TEXT_LEN
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

/// Generate a base64-encoded random TSIG secret.
fn generate_secret() -> String {
    let bytes: [u8; GENERATED_SECRET_LEN] = rand::rng().random();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub mod grant;

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::error::ErrorCode;

    /// Verify that `normalize_key_name` lowercases and strips trailing dot.
    #[test]
    fn normalize_key_name_lowercases_and_strips_trailing_dot() {
        assert_eq!(
            normalize_key_name("Nsupdate-Key.Example.COM.").unwrap(),
            "nsupdate-key.example.com"
        );
        assert_eq!(normalize_key_name(" update-key ").unwrap(), "update-key");
    }

    /// Verify that `normalize_key_name` rejects invalid names.
    #[test]
    fn normalize_key_name_rejects_invalid_names() {
        for invalid in ["", ".", "bad name", "bad..label", &"a".repeat(300)] {
            let err = normalize_key_name(invalid).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput, "input: {:?}", invalid);
        }
    }

    /// Verify that `normalize_key_name` holds the rendered name to the column.
    #[test]
    fn normalize_key_name_holds_the_rendered_name_to_the_column() {
        // A label of escaped dots renders four characters per byte, so a name
        // the wire admits can still outgrow `tsig_keys.name`.
        let fits = format!("{}.key", r"\.".repeat(62));
        let too_long = format!("{}.{}", r"\.".repeat(40), r"\.".repeat(40));

        assert_eq!(normalize_key_name(&fits).unwrap().len(), 252);
        assert_eq!(
            normalize_key_name(&too_long).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    /// Verify that `normalize_secret` accepts base64 and rejects garbage.
    #[test]
    fn normalize_secret_accepts_base64_and_rejects_garbage() {
        // 32-byte imported secret, whitespace trimmed.
        assert_eq!(
            normalize_secret(" bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU= ").unwrap(),
            "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=".to_string()
        );

        let invalid = normalize_secret("not base64!!").unwrap_err();
        assert_eq!(invalid.code(), ErrorCode::InvalidInput);

        let empty = normalize_secret("").unwrap_err();
        assert_eq!(empty.code(), ErrorCode::InvalidInput);
    }

    /// Verify that `normalize_secret` enforces length bounds.
    #[test]
    fn normalize_secret_enforces_length_bounds() {
        // 6 decoded bytes: far below the 128-bit minimum.
        let short = normalize_secret("c2VjcmV0").unwrap_err();
        assert_eq!(short.code(), ErrorCode::InvalidInput);
        assert!(short.to_string().contains("at least 16 bytes"));

        // Exactly 16 decoded bytes passes.
        let sixteen = base64::engine::general_purpose::STANDARD.encode([0x42u8; 16]);
        normalize_secret(&sixteen).unwrap();

        // The base64 form must fit the VARCHAR(255) column.
        let oversized = base64::engine::general_purpose::STANDARD.encode([0x42u8; 200]);
        assert!(oversized.len() > 255);
        let too_long = normalize_secret(&oversized).unwrap_err();
        assert_eq!(too_long.code(), ErrorCode::InvalidInput);
        assert!(too_long.to_string().contains("at most 255"));
    }
}
