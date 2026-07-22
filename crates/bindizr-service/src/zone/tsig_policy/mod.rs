use chrono::Utc;

use crate::{
    RepositoryTx,
    error::ServiceError,
    model::{record::RecordType, tsig_key::TsigKey, zone_tsig_policy::ZoneTsigPolicy},
    repository::RepositoryService,
    tsig_key::normalize_key_name,
    validation::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN, has_whitespace_or_control},
    zone::validation::normalize_zone_name,
};

/// Pattern/type values granting unrestricted rights.
const MATCH_ANY: &str = "*";

/// A zone TSIG policy joined with the name of the key it grants.
#[derive(Debug, Clone)]
pub struct ZoneTsigPolicyWithKey {
    pub policy: ZoneTsigPolicy,
    pub tsig_key_name: String,
}

/// Grants and revokes per-zone nsupdate rights for TSIG keys.
pub struct ZoneTsigPolicyService;

impl ZoneTsigPolicyService {
    /// Grant `key_name` nsupdate rights in `zone_name`, optionally restricted
    /// to a record name pattern and/or record types. Global keys are rejected:
    /// they already cover every zone and never carry policies.
    pub async fn add(
        zone_name: &str,
        key_name: &str,
        record_name_pattern: Option<&str>,
        record_types: Option<&str>,
    ) -> Result<ZoneTsigPolicyWithKey, ServiceError> {
        let zone = find_zone(zone_name).await?;
        let key = find_key(key_name).await?;

        if key.is_global {
            return Err(ServiceError::invalid_input(format!(
                "TSIG key '{}' is global and already covers every zone; policies cannot be added to it",
                key.name
            )));
        }

        let record_name_pattern = normalize_pattern(record_name_pattern)?;
        let record_types = normalize_types(record_types)?;

        let policy = RepositoryService::create_zone_tsig_policy(ZoneTsigPolicy {
            id: 0,
            zone_id: zone.id,
            tsig_key_id: key.id,
            record_name_pattern,
            record_types,
            created_at: Utc::now(),
        })
        .await?;

        Ok(ZoneTsigPolicyWithKey {
            policy,
            tsig_key_name: key.name,
        })
    }

    /// List all TSIG policies of a zone with their key names.
    pub async fn list(zone_name: &str) -> Result<Vec<ZoneTsigPolicyWithKey>, ServiceError> {
        let zone = find_zone(zone_name).await?;
        let policies = RepositoryService::get_zone_tsig_policies_by_zone_id(zone.id).await?;

        let keys = RepositoryService::get_all_tsig_keys().await?;
        let key_name = |id: i32| {
            keys.iter()
                .find(|key| key.id == id)
                .map(|key| key.name.clone())
                .unwrap_or_default()
        };

        Ok(policies
            .into_iter()
            .map(|policy| ZoneTsigPolicyWithKey {
                tsig_key_name: key_name(policy.tsig_key_id),
                policy,
            })
            .collect())
    }

    /// Remove one policy of a zone by policy id.
    pub async fn remove(zone_name: &str, policy_id: i32) -> Result<(), ServiceError> {
        let zone = find_zone(zone_name).await?;

        let policy = RepositoryService::get_zone_tsig_policy_by_id(policy_id)
            .await?
            .filter(|policy| policy.zone_id == zone.id)
            .ok_or_else(|| ServiceError::tsig_policy_not_found(policy_id))?;

        RepositoryService::delete_zone_tsig_policy(policy.id).await
    }

    /// Policies granting `tsig_key_id` rights in `zone_id`, within the caller's
    /// transaction. Used by the nsupdate path.
    pub async fn get_by_zone_and_key_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        tsig_key_id: i32,
    ) -> Result<Vec<ZoneTsigPolicy>, ServiceError> {
        RepositoryService::get_zone_tsig_policies_by_zone_and_key_tx(tx, zone_id, tsig_key_id).await
    }
}

/// Whether any policy authorizes an update of `record_type` at the relative
/// owner name. `record_type` is `None` for whole-name deletes (wire TYPE ANY),
/// which only a policy with unrestricted types may authorize.
pub fn authorize_update(
    policies: &[ZoneTsigPolicy],
    relative_name: &str,
    record_type: Option<&RecordType>,
) -> bool {
    policies.iter().any(|policy| {
        pattern_matches_name(&policy.record_name_pattern, relative_name)
            && types_match(&policy.record_types, record_type)
    })
}

/// Match a relative owner name (`@`, `www`, `a.b`, ...) against a policy
/// pattern: `*` (any name), `@` (apex only), `*.sub` (sub and everything under
/// it), or an exact relative name.
fn pattern_matches_name(pattern: &str, relative_name: &str) -> bool {
    let name = relative_name.to_ascii_lowercase();

    if pattern == MATCH_ANY {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        return name == suffix || name.ends_with(&format!(".{}", suffix));
    }

    name == pattern
}

fn types_match(types: &str, record_type: Option<&RecordType>) -> bool {
    if types == MATCH_ANY {
        return true;
    }

    match record_type {
        // A whole-name delete touches every type at the name, so a type-limited
        // policy cannot cover it.
        None => false,
        Some(record_type) => types.split(',').any(|t| t == record_type.as_str()),
    }
}

async fn find_zone(zone_name: &str) -> Result<crate::model::zone::Zone, ServiceError> {
    let name = normalize_zone_name(zone_name)?;
    RepositoryService::get_zone_by_name(&name)
        .await?
        .ok_or_else(|| ServiceError::zone_not_found(zone_name))
}

async fn find_key(key_name: &str) -> Result<TsigKey, ServiceError> {
    let name = normalize_key_name(key_name)?;
    RepositoryService::get_tsig_key_by_name(&name)
        .await?
        .ok_or_else(|| ServiceError::tsig_key_not_found(&name))
}

/// Normalize and validate a record name pattern; `None` grants all names.
fn normalize_pattern(value: Option<&str>) -> Result<String, ServiceError> {
    let raw = match value.map(str::trim) {
        None | Some("") => return Ok(MATCH_ANY.to_string()),
        Some(raw) => raw,
    };

    if raw == MATCH_ANY || raw == "@" {
        return Ok(raw.to_string());
    }

    let name_part = raw.strip_prefix("*.").unwrap_or(raw);
    validate_relative_name(name_part)?;

    Ok(raw.to_ascii_lowercase())
}

fn validate_relative_name(name: &str) -> Result<(), ServiceError> {
    if name.is_empty() {
        return Err(ServiceError::invalid_input(
            "record name pattern must not be empty",
        ));
    }

    if has_whitespace_or_control(name) || name.contains('*') {
        return Err(ServiceError::invalid_input(format!(
            "invalid record name pattern '{}': use '*', '@', '*.<name>' or an exact relative name",
            name
        )));
    }

    if name.len() > MAX_DOMAIN_LEN {
        return Err(ServiceError::invalid_input(
            "record name pattern must be 253 bytes or fewer",
        ));
    }

    for label in name.split('.') {
        if label.is_empty() {
            return Err(ServiceError::invalid_input(
                "record name pattern must not contain empty labels",
            ));
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(ServiceError::invalid_input(
                "record name pattern labels must be 63 bytes or fewer",
            ));
        }
    }

    Ok(())
}

/// Normalize and validate a record type list; `None` grants all types.
fn normalize_types(value: Option<&str>) -> Result<String, ServiceError> {
    let raw = match value.map(str::trim) {
        None | Some("") => return Ok(MATCH_ANY.to_string()),
        Some(raw) => raw,
    };

    if raw == MATCH_ANY {
        return Ok(MATCH_ANY.to_string());
    }

    let mut types: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let record_type: RecordType = part.trim().parse().map_err(ServiceError::invalid_input)?;
        let name = record_type.as_str().to_string();
        if !types.contains(&name) {
            types.push(name);
        }
    }

    Ok(types.join(","))
}

#[cfg(test)]
mod tests;
