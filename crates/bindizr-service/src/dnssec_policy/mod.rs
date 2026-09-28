//! DNSSEC policies: the named signing-parameter bundles zones sign under.
//! Partial updates lock the policy row; creates and deletes rely on constraints.
//! Zone signing consumes these policies in `dnssec`.

use chrono::Utc;

use crate::{
    Context,
    authorization::Caller,
    db,
    db::LockLevel,
    error::{ErrorCode, ServiceError},
    model::{
        dnssec_key::DnssecAlgorithm,
        dnssec_policy::{DEFAULT_DNSSEC_POLICY_NAME, DnssecDenial, DnssecPolicy},
    },
    text::normalize_identifier,
    transaction,
    types::{
        CreateDnssecPolicyRequest, GetDnssecPolicyResponse, PageFilter, PaginatedResponse,
        UpdateDnssecPolicyRequest,
    },
};

/// RFC 1982 serial arithmetic is only unambiguous while expiration -
/// inception stays under 2^31 seconds (RFC 4034, Section 3.1.5).
const MAX_SIGNATURE_VALIDITY_DAYS: u32 = 24_855;
/// Cap on scheduled-roll lifetimes: a typo must not park a ZSK for decades.
const MAX_ZSK_LIFETIME_DAYS: u32 = 3650;
const MAX_POLICY_NAME_LEN: usize = 64;

/// Create a policy; omitted fields take the built-in defaults.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: CreateDnssecPolicyRequest,
) -> Result<DnssecPolicy, ServiceError> {
    caller.authorize_global("manage DNSSEC policies")?;

    let name = normalize_policy_name(&request.name)?;
    let algorithm = match request.algorithm.as_deref() {
        Some(raw) => raw
            .parse::<DnssecAlgorithm>()
            .map_err(ServiceError::invalid_input)?,
        None => DnssecAlgorithm::EcdsaP256Sha256,
    };
    let denial = match request.denial.as_deref() {
        Some(raw) => raw
            .parse::<DnssecDenial>()
            .map_err(ServiceError::invalid_input)?,
        // NSEC leaves the zone walkable, so a policy that did not
        // choose is not opted into it.
        None => DnssecDenial::Nsec3,
    };
    let signature_validity_days = request.signature_validity_days.unwrap_or(14);
    let signature_refresh_days = request.signature_refresh_days.unwrap_or(5);
    let zsk_lifetime_days = request.zsk_lifetime_days.unwrap_or(0);
    validate_timing(
        signature_validity_days,
        signature_refresh_days,
        zsk_lifetime_days,
    )?;

    // Friendly pre-check; the UNIQUE(name) backstop covers the race.
    if db::dnssec_policy::get_by_name(cx.db(), &name)
        .await?
        .is_some()
    {
        return Err(ServiceError::dnssec_policy_conflict(&name));
    }

    db::dnssec_policy::create(
        cx.db(),
        DnssecPolicy {
            id: 0,
            name: name.clone(),
            algorithm,
            denial,
            split_keys: request.split_keys,
            signature_validity_days: signature_validity_days as i32,
            signature_refresh_days: signature_refresh_days as i32,
            zsk_lifetime_days: zsk_lifetime_days as i32,
            created_at: Utc::now(),
        },
    )
    .await
    .map_err(|e| {
        // A create that raced past the pre-check trips UNIQUE(name); the
        // backstop reads as the same conflict.
        if e.is_unique_violation() {
            ServiceError::dnssec_policy_conflict(&name)
        } else {
            e.into()
        }
    })
}

/// List DNSSEC policies visible to an authorized caller.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    page: PageFilter,
) -> Result<PaginatedResponse<GetDnssecPolicyResponse>, ServiceError> {
    caller.authorize_global("manage DNSSEC policies")?;

    let policies = db::dnssec_policy::list_all(cx.db()).await?;
    PaginatedResponse::from_collection(
        policies
            .iter()
            .map(GetDnssecPolicyResponse::from_policy)
            .collect(),
        page.limit,
        page.offset,
    )
}

/// Load a named DNSSEC policy for an authorized caller.
pub async fn get(cx: &Context, caller: &Caller, name: &str) -> Result<DnssecPolicy, ServiceError> {
    caller.authorize_global("manage DNSSEC policies")?;

    lookup_by_name(cx, name).await
}

/// Fetch one policy by name. This is the unchecked lookup for
/// service-internal use; front ends go through [`get`].
pub(crate) async fn lookup_by_name(cx: &Context, name: &str) -> Result<DnssecPolicy, ServiceError> {
    let name = normalize_policy_name(name)?;
    db::dnssec_policy::get_by_name(cx.db(), &name)
        .await?
        .ok_or_else(|| ServiceError::dnssec_policy_not_found(&name))
}

/// Edit the policy's timing fields; the key layout, algorithm, and
/// denial mode are fixed at creation. Zones under the policy pick the
/// new values up on their next signing pass or scheduler scan.
pub async fn update(
    cx: &Context,
    caller: &Caller,
    name: &str,
    request: UpdateDnssecPolicyRequest,
) -> Result<DnssecPolicy, ServiceError> {
    caller.authorize_global("manage DNSSEC policies")?;
    let name = normalize_policy_name(name)?;

    // Read and write under the row lock, or two partial updates would
    // each restore the fields the other changed.
    let mut tx = transaction::begin_tx(cx, "failed to update DNSSEC policy").await?;
    let result: Result<_, ServiceError> = async {
        let policy = db::dnssec_policy::get_by_name_tx(&mut tx, &name, LockLevel::Exclusive)
            .await?
            .ok_or_else(|| ServiceError::dnssec_policy_not_found(&name))?;
        let signature_validity_days = request
            .signature_validity_days
            .unwrap_or(policy.signature_validity_days as u32);
        let signature_refresh_days = request
            .signature_refresh_days
            .unwrap_or(policy.signature_refresh_days as u32);
        let zsk_lifetime_days = request
            .zsk_lifetime_days
            .unwrap_or(policy.zsk_lifetime_days as u32);
        validate_timing(
            signature_validity_days,
            signature_refresh_days,
            zsk_lifetime_days,
        )?;

        Ok(db::dnssec_policy::update_tx(
            &mut tx,
            DnssecPolicy {
                signature_validity_days: signature_validity_days as i32,
                signature_refresh_days: signature_refresh_days as i32,
                zsk_lifetime_days: zsk_lifetime_days as i32,
                ..policy
            },
        )
        .await?)
    }
    .await;
    transaction::finish_tx(tx, result, "failed to update DNSSEC policy").await
}

/// Delete a policy by name; refused for the built-in `default` and while
/// any zone signs under it.
pub async fn delete(cx: &Context, caller: &Caller, name: &str) -> Result<(), ServiceError> {
    caller.authorize_global("manage DNSSEC policies")?;

    let policy = lookup_by_name(cx, name).await?;
    // `enable` and `keys import` fall back to it by name.
    if policy.name == DEFAULT_DNSSEC_POLICY_NAME {
        return Err(ServiceError::invalid_input(format!(
            "the built-in '{}' policy cannot be deleted; edit it instead",
            DEFAULT_DNSSEC_POLICY_NAME
        )));
    }

    let zone_count = db::zone::count_by_dnssec_policy_id(cx.db(), policy.id).await?;
    if zone_count > 0 {
        return Err(ServiceError::dnssec_policy_in_use(&policy.name, zone_count));
    }

    db::dnssec_policy::delete(cx.db(), policy.id)
        .await
        .map_err(|e| {
            // A zone enabled between the count above and this delete trips
            // the FK; it reads as the in-use conflict.
            if e.is_foreign_key_violation() {
                ServiceError::new(
                    ErrorCode::DnssecPolicyInUse,
                    "DNSSEC policy is still used by signed zones",
                )
            } else {
                e.into()
            }
        })
}

/// Lowercased so one name means one policy on every backend (MySQL compares
/// case-insensitively); a plain identifier, since it travels in URL paths.
pub(crate) fn normalize_policy_name(value: &str) -> Result<String, ServiceError> {
    normalize_identifier(value, "DNSSEC policy name", MAX_POLICY_NAME_LEN)
}

/// Validate signature validity, refresh, and key lifetime settings.
///
/// The refresh window must be shorter than validity, or every scheduler pass would re-sign
/// the zone.
fn validate_timing(
    signature_validity_days: u32,
    signature_refresh_days: u32,
    zsk_lifetime_days: u32,
) -> Result<(), ServiceError> {
    if signature_validity_days == 0 {
        return Err(ServiceError::invalid_input(
            "signature_validity_days must be greater than 0",
        ));
    }
    if signature_validity_days > MAX_SIGNATURE_VALIDITY_DAYS {
        return Err(ServiceError::invalid_input(format!(
            "signature_validity_days must be at most {} (2^31 seconds)",
            MAX_SIGNATURE_VALIDITY_DAYS
        )));
    }
    if signature_refresh_days == 0 {
        return Err(ServiceError::invalid_input(
            "signature_refresh_days must be greater than 0",
        ));
    }
    if signature_refresh_days >= signature_validity_days {
        return Err(ServiceError::invalid_input(format!(
            "signature_refresh_days ({}) must be less than signature_validity_days ({})",
            signature_refresh_days, signature_validity_days
        )));
    }
    if zsk_lifetime_days > MAX_ZSK_LIFETIME_DAYS {
        return Err(ServiceError::invalid_input(format!(
            "zsk_lifetime_days must be at most {}",
            MAX_ZSK_LIFETIME_DAYS
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{normalize_policy_name, validate_timing};

    /// Verify that `normalize_policy_name` lowercases and trims.
    #[test]
    fn normalize_policy_name_lowercases_and_trims() {
        assert_eq!(normalize_policy_name("  Strict-1 ").unwrap(), "strict-1");
    }

    /// Verify that `normalize_policy_name` rejects empty and odd characters.
    #[test]
    fn normalize_policy_name_rejects_empty_and_odd_characters() {
        assert!(normalize_policy_name("   ").is_err());
        assert!(normalize_policy_name("a b").is_err());
        assert!(normalize_policy_name("a/b").is_err());
        assert!(normalize_policy_name(&"x".repeat(65)).is_err());
    }

    /// Verify that `validate_timing` requires refresh below validity.
    #[test]
    fn validate_timing_requires_refresh_below_validity() {
        assert!(validate_timing(14, 5, 0).is_ok());
        assert!(validate_timing(5, 5, 0).is_err());
        assert!(validate_timing(0, 1, 0).is_err());
        assert!(validate_timing(14, 0, 0).is_err());
        // RFC 4034, Section 3.1.5: serial arithmetic wraps at 2^31 seconds.
        assert!(validate_timing(24_856, 5, 0).is_err());
        assert!(validate_timing(24_855, 5, 0).is_ok());
        assert!(validate_timing(14, 5, 3651).is_err());
    }
}
