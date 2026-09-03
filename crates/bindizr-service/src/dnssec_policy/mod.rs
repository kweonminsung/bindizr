//! DNSSEC policies: the named signing-parameter bundles zones sign under.
//! A policy row is a management write (single statements, constraints as
//! the backstop); the zone side that consumes it lives in `dnssec`.

use chrono::Utc;

use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    model::{
        dnssec_key::DnssecAlgorithm,
        dnssec_policy::{DnssecDenial, DnssecPolicy},
    },
    repository::RepositoryService,
    types::{CreateDnssecPolicyRequest, UpdateDnssecPolicyRequest},
};

/// RFC 1982 serial arithmetic is only unambiguous while expiration -
/// inception stays under 2^31 seconds (RFC 4034, Section 3.1.5).
const MAX_SIGNATURE_VALIDITY_DAYS: u32 = 24_855;
/// Cap on scheduled-roll lifetimes: a typo must not park a ZSK for decades.
const MAX_ZSK_LIFETIME_DAYS: u32 = 3650;
const MAX_POLICY_NAME_LEN: usize = 64;

/// Creates, lists, edits, and deletes DNSSEC policies.
pub struct DnssecPolicyService;

impl DnssecPolicyService {
    /// Create a policy; omitted fields take the built-in defaults.
    pub async fn create(
        caller: &Caller,
        request: CreateDnssecPolicyRequest,
    ) -> Result<DnssecPolicy, ServiceError> {
        caller.require_global("manage DNSSEC policies")?;

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
            None => DnssecDenial::Nsec,
        };
        let signature_validity_days = request.signature_validity_days.unwrap_or(14);
        let signature_refresh_days = request.signature_refresh_days.unwrap_or(5);
        let zsk_lifetime_days = request.zsk_lifetime_days.unwrap_or(0);
        validate_timing(
            signature_validity_days,
            signature_refresh_days,
            zsk_lifetime_days,
        )?;

        if RepositoryService::get_dnssec_policy_by_name(&name)
            .await?
            .is_some()
        {
            return Err(ServiceError::dnssec_policy_conflict(&name));
        }

        RepositoryService::create_dnssec_policy(DnssecPolicy {
            id: 0,
            name,
            algorithm,
            denial,
            split_keys: request.split_keys,
            signature_validity_days: signature_validity_days as i32,
            signature_refresh_days: signature_refresh_days as i32,
            zsk_lifetime_days: zsk_lifetime_days as i32,
            rollover_publish_holddown_secs: i64::from(
                request.rollover_publish_holddown_secs.unwrap_or(86_400),
            ),
            rollover_retire_holddown_secs: i64::from(
                request.rollover_retire_holddown_secs.unwrap_or(172_800),
            ),
            created_at: Utc::now(),
        })
        .await
    }

    pub async fn list(caller: &Caller) -> Result<Vec<DnssecPolicy>, ServiceError> {
        caller.require_global("manage DNSSEC policies")?;

        RepositoryService::list_dnssec_policies().await
    }

    pub async fn get(caller: &Caller, name: &str) -> Result<DnssecPolicy, ServiceError> {
        caller.require_global("manage DNSSEC policies")?;

        Self::lookup_by_name(name).await
    }

    /// Fetch one policy by name. This is the unchecked lookup for
    /// service-internal use; front ends go through [`Self::get`].
    pub(crate) async fn lookup_by_name(name: &str) -> Result<DnssecPolicy, ServiceError> {
        let name = normalize_policy_name(name)?;
        RepositoryService::get_dnssec_policy_by_name(&name)
            .await?
            .ok_or_else(|| ServiceError::dnssec_policy_not_found(&name))
    }

    /// Edit the policy's timing fields; the key layout, algorithm, and
    /// denial mode are fixed at creation. Zones under the policy pick the
    /// new values up on their next signing pass or maintenance scan.
    pub async fn update(
        caller: &Caller,
        name: &str,
        request: UpdateDnssecPolicyRequest,
    ) -> Result<DnssecPolicy, ServiceError> {
        caller.require_global("manage DNSSEC policies")?;
        let name = normalize_policy_name(name)?;

        // Read and write under the row lock, or two partial updates would
        // each restore the fields the other changed.
        let mut tx = RepositoryService::begin_tx("failed to update DNSSEC policy").await?;
        let result = async {
            let policy = RepositoryService::get_dnssec_policy_by_name_tx(
                &mut tx,
                &name,
                LockLevel::Exclusive,
            )
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

            RepositoryService::update_dnssec_policy_tx(
                &mut tx,
                DnssecPolicy {
                    signature_validity_days: signature_validity_days as i32,
                    signature_refresh_days: signature_refresh_days as i32,
                    zsk_lifetime_days: zsk_lifetime_days as i32,
                    rollover_publish_holddown_secs: request
                        .rollover_publish_holddown_secs
                        .map_or(policy.rollover_publish_holddown_secs, i64::from),
                    rollover_retire_holddown_secs: request
                        .rollover_retire_holddown_secs
                        .map_or(policy.rollover_retire_holddown_secs, i64::from),
                    ..policy
                },
            )
            .await
        }
        .await;
        RepositoryService::finish_tx(tx, result, "failed to update DNSSEC policy").await
    }

    /// Delete a policy by name; refused while any zone signs under it.
    pub async fn delete(caller: &Caller, name: &str) -> Result<(), ServiceError> {
        caller.require_global("manage DNSSEC policies")?;

        let policy = Self::lookup_by_name(name).await?;

        let zone_count = RepositoryService::count_zones_by_dnssec_policy_id(policy.id).await?;
        if zone_count > 0 {
            return Err(ServiceError::dnssec_policy_in_use(&policy.name, zone_count));
        }

        RepositoryService::delete_dnssec_policy(policy.id).await
    }
}

/// Lowercased so one name means one policy on every backend (MySQL compares
/// case-insensitively); a plain identifier, since it travels in URL paths.
pub(crate) fn normalize_policy_name(value: &str) -> Result<String, ServiceError> {
    let name = value.trim().to_lowercase();

    if name.is_empty() {
        return Err(ServiceError::invalid_input(
            "DNSSEC policy name must not be empty",
        ));
    }
    if name.len() > MAX_POLICY_NAME_LEN {
        return Err(ServiceError::invalid_input(format!(
            "DNSSEC policy name must be {} characters or fewer",
            MAX_POLICY_NAME_LEN
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(ServiceError::invalid_input(
            "DNSSEC policy name may contain only letters, digits, '-', '_', and '.'",
        ));
    }
    Ok(name)
}

/// A refresh window at least as long as the validity would re-sign on every
/// pass; requiring headroom keeps re-signing periodic and expiry reachable.
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

    #[test]
    fn normalize_policy_name_lowercases_and_trims() {
        assert_eq!(normalize_policy_name("  Strict-1 ").unwrap(), "strict-1");
    }

    #[test]
    fn normalize_policy_name_rejects_empty_and_odd_characters() {
        assert!(normalize_policy_name("   ").is_err());
        assert!(normalize_policy_name("a b").is_err());
        assert!(normalize_policy_name("a/b").is_err());
        assert!(normalize_policy_name(&"x".repeat(65)).is_err());
    }

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
