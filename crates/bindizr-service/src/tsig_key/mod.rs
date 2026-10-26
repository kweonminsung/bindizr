//! Manages TSIG credentials shared by update and transfer authentication.

use std::collections::HashMap;

use base64::Engine;
use bindizr_core::dns::name;
use bindizr_core::model::audit_log::{AuditEntity, AuditOperation};
use bindizr_core::model::role::RoleId;
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::tsig_key::TsigKeyId;
use chrono::Utc;
use rand::RngExt;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::model::tsig_key::{TsigAlgorithm, TsigKey};
use crate::text::MAX_COLUMN_TEXT_LEN;
use crate::types::{
    CreateTsigKeyRequest, PaginatedResponse, SingleTsigKeyResponse, TsigKeyFilter, TsigKeyResponse,
};
use crate::{Context, audit, pagination, role, transaction};

/// Create a TSIG key in the request's role. An omitted `secret` is generated;
/// a given one must be valid, non-empty base64 (an imported key).
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateTsigKeyRequest,
) -> Result<SingleTsigKeyResponse, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let name = normalize_key_name(&request.name)?;

    let role = role::lookup_by_name(cx, &request.role_name).await?;

    let algorithm = request
        .algorithm
        .as_deref()
        .map(str::parse::<TsigAlgorithm>)
        .transpose()
        .map_err(ServiceError::invalid_input)?
        .unwrap_or_default();
    let secret = match request.secret.as_deref() {
        Some(secret) => normalize_secret(secret)?,
        None => generate_secret(&algorithm),
    };

    // Friendly pre-check; the UNIQUE(name) backstop covers the race.
    if bindizr_db::tsig_key::get_by_name(cx.db(), &name)
        .await?
        .is_some()
    {
        return Err(ServiceError::tsig_key_conflict(&name));
    }

    let mut tx = transaction::begin_tx(cx, "failed to create TSIG key").await?;
    let result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;
        let tsig_key = bindizr_db::tsig_key::create_tx(
            &mut tx,
            TsigKey {
                id: TsigKeyId::UNWRITTEN,
                name: name.clone(),
                algorithm,
                secret,
                role_id: role.id,
                created_at: Utc::now(),
            },
        )
        .await
        .map_err(|error| {
            // A create that raced past the pre-check trips UNIQUE(name); the
            // backstop reads as the same conflict.
            if error.is_unique_violation() {
                ServiceError::tsig_key_conflict(&name)
            } else if error.is_foreign_key_violation() {
                ServiceError::role_not_found(&role.name)
            } else {
                error.into()
            }
        })?;
        audit::save_tx(
            &mut tx,
            AuditEntity::TsigKey,
            &tsig_key.name,
            AuditOperation::Create,
            Some(format!(
                "role_name {}, algorithm {}",
                role.name, tsig_key.algorithm
            )),
            caller.change_origin(),
        )
        .await?;

        Ok(tsig_key)
    }
    .await;
    let tsig_key = transaction::finish_tx(tx, result, "failed to create TSIG key").await?;

    Ok(SingleTsigKeyResponse::from_tsig_key(&tsig_key, &role.name))
}

/// List the TSIG keys, every one or one role's.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    filter: &TsigKeyFilter,
) -> Result<PaginatedResponse<TsigKeyResponse>, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;
    pagination::validate_page_limit(filter.limit)?;

    let keys = match &filter.role_name {
        Some(role_name) => {
            let role = role::lookup_by_name(cx, role_name).await?;
            bindizr_db::tsig_key::list_by_role_id(cx.db(), role.id).await?
        }
        None => bindizr_db::tsig_key::list_all(cx.db()).await?,
    };
    let role_names: HashMap<RoleId, String> = bindizr_db::role::list_all(cx.db())
        .await?
        .into_iter()
        .map(|role| (role.id, role.name))
        .collect();

    Ok(pagination::build_page(
        keys.iter()
            .map(|tsig_key| {
                let role_name = role_names.get(&tsig_key.role_id).map_or("", String::as_str);
                TsigKeyResponse::from_tsig_key(tsig_key, role_name)
            })
            .collect(),
        filter.limit,
        filter.offset,
    ))
}

/// Fetch one TSIG key by name, including its secret.
pub async fn get(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<SingleTsigKeyResponse, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let tsig_key = lookup_by_name(cx, name).await?;
    let role = bindizr_db::role::get(cx.db(), tsig_key.role_id)
        .await?
        .ok_or_else(|| ServiceError::role_not_found(tsig_key.role_id))?;

    Ok(SingleTsigKeyResponse::from_tsig_key(&tsig_key, &role.name))
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

/// Delete a TSIG key by name; refused while it signs a secondary's NOTIFY.
pub async fn delete(cx: &Context, caller: &Caller, name: &str) -> Result<(), ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let tsig_key = lookup_by_name(cx, name).await?;

    let secondary_count =
        bindizr_db::secondary::count_by_notify_tsig_key_id(cx.db(), tsig_key.id).await?;

    if secondary_count > 0 {
        return Err(ServiceError::TsigKeyInUse(format!(
            "TSIG key '{}' still signs NOTIFY for {} secondar{}",
            tsig_key.name,
            secondary_count,
            if secondary_count == 1 { "y" } else { "ies" }
        )));
    }

    let mut tx = transaction::begin_tx(cx, "failed to delete TSIG key").await?;
    let result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;
        let deleted = bindizr_db::tsig_key::delete_tx(&mut tx, tsig_key.id)
            .await
            .map_err(|error| {
                // A secondary that took the key between the count above and this
                // delete trips the FK: the same in-use conflict.
                if error.is_foreign_key_violation() {
                    ServiceError::TsigKeyInUse(
                        "TSIG key still signs NOTIFY for a secondary".to_string(),
                    )
                } else {
                    error.into()
                }
            })?;

        // Removed meanwhile: not found, and no audit row for a deletion that was not one.
        if !deleted {
            return Err(ServiceError::tsig_key_not_found(&tsig_key.name));
        }

        audit::save_tx(
            &mut tx,
            AuditEntity::TsigKey,
            &tsig_key.name,
            AuditOperation::Delete,
            None,
            caller.change_origin(),
        )
        .await
    }
    .await;

    transaction::finish_tx(tx, result, "failed to delete TSIG key").await
}

/// Normalize a TSIG key name: it travels in the TSIG record's NAME field, so
/// it must be a valid domain name. Stored lowercase without the trailing dot.
pub(crate) fn normalize_key_name(value: &str) -> Result<String, ServiceError> {
    let name = name::parse_lookup_name(value)
        .map_err(|error| ServiceError::invalid_input(format!("TSIG key name {}", error)))?;

    if name.len() > MAX_COLUMN_TEXT_LEN {
        return Err(ServiceError::invalid_input(format!(
            "TSIG key name must be {} characters or fewer in its canonical spelling",
            MAX_COLUMN_TEXT_LEN
        )));
    }

    Ok(name)
}

/// Imported secrets must contain at least 128 bits.
// RFC 8945, Section 8 recommends output-sized keys; shorter imports preserve
// secrets already shared with other servers.
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
        .map_err(|error| {
            ServiceError::invalid_input(format!("TSIG key secret must be valid base64: {}", error))
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

/// Generate a base64 secret as long as the HMAC output (RFC 8945, Section 8).
fn generate_secret(algorithm: &TsigAlgorithm) -> String {
    let bytes: [u8; 64] = rand::rng().random();
    base64::engine::general_purpose::STANDARD.encode(&bytes[..algorithm.digest_len()])
}

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
            let error = normalize_key_name(invalid).unwrap_err();

            assert_eq!(
                error.code(),
                ErrorCode::InvalidInput,
                "input: {:?}",
                invalid
            );
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
