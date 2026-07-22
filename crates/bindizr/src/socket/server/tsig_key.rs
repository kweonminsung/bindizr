use bindizr_service::{
    error::ServiceError, tsig_key::TsigKeyService, zone::tsig_policy::ZoneTsigPolicyService,
};

use crate::{
    api::types::{GetTsigKeyResponse, GetZoneTsigPolicyResponse},
    socket::types::DaemonResponse,
};

fn required_str<'a>(
    data: &'a serde_json::Value,
    field: &'static str,
) -> Result<&'a str, ServiceError> {
    data.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ServiceError::invalid_input(format!("Missing or invalid '{}' field", field)))
}

fn optional_str<'a>(data: &'a serde_json::Value, field: &'static str) -> Option<&'a str> {
    data.get(field).and_then(|v| v.as_str())
}

fn to_response_data<T: serde::Serialize>(value: T) -> Result<serde_json::Value, ServiceError> {
    serde_json::to_value(value)
        .map_err(|e| ServiceError::internal(format!("Failed to serialize response: {}", e)))
}

/// Handle the `TsigKeyCreate` command by creating (or importing) a TSIG key.
pub(super) async fn create_tsig_key(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let name = required_str(data, "name")?;
    let algorithm = optional_str(data, "algorithm");
    let secret = optional_str(data, "secret");
    let is_global = data
        .get("global")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let key = TsigKeyService::create(name, algorithm, secret, is_global).await?;

    Ok(DaemonResponse {
        message: "TSIG key created successfully".to_string(),
        data: to_response_data(GetTsigKeyResponse::from_key(&key))?,
    })
}

/// Handle the `TsigKeyList` command by returning all TSIG keys without secrets.
pub(super) async fn list_tsig_keys() -> Result<DaemonResponse, ServiceError> {
    let keys = TsigKeyService::list().await?;
    let keys: Vec<GetTsigKeyResponse> = keys.iter().map(GetTsigKeyResponse::from_key).collect();

    Ok(DaemonResponse {
        message: "TSIG keys retrieved successfully".to_string(),
        data: to_response_data(keys)?,
    })
}

/// Handle the `TsigKeyGet` command by returning one TSIG key with its secret.
pub(super) async fn get_tsig_key(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let name = required_str(data, "name")?;

    let key = TsigKeyService::get(name).await?;

    Ok(DaemonResponse {
        message: "TSIG key retrieved successfully".to_string(),
        data: to_response_data(GetTsigKeyResponse::from_key(&key))?,
    })
}

/// Handle the `TsigKeyDelete` command by deleting an unused TSIG key.
pub(super) async fn delete_tsig_key(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let name = required_str(data, "name")?;

    TsigKeyService::delete(name).await?;

    Ok(DaemonResponse {
        message: "TSIG key deleted successfully".to_string(),
        data: serde_json::Value::Null,
    })
}

/// Handle the `ZoneTsigPolicyAdd` command by granting a key rights in a zone.
pub(super) async fn add_zone_tsig_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let zone_name = required_str(data, "zone_name")?;
    let key_name = required_str(data, "tsig_key")?;
    let pattern = optional_str(data, "record_name_pattern");
    let types = optional_str(data, "record_types");

    let policy = ZoneTsigPolicyService::add(zone_name, key_name, pattern, types).await?;

    Ok(DaemonResponse {
        message: "TSIG policy created successfully".to_string(),
        data: to_response_data(GetZoneTsigPolicyResponse::from_policy(&policy))?,
    })
}

/// Handle the `ZoneTsigPolicyList` command by returning a zone's policies.
pub(super) async fn list_zone_tsig_policies(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let zone_name = required_str(data, "zone_name")?;

    let policies = ZoneTsigPolicyService::list(zone_name).await?;
    let policies: Vec<GetZoneTsigPolicyResponse> = policies
        .iter()
        .map(GetZoneTsigPolicyResponse::from_policy)
        .collect();

    Ok(DaemonResponse {
        message: "TSIG policies retrieved successfully".to_string(),
        data: to_response_data(policies)?,
    })
}

/// Handle the `ZoneTsigPolicyRemove` command by removing one policy of a zone.
pub(super) async fn remove_zone_tsig_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let zone_name = required_str(data, "zone_name")?;
    let policy_id = required_policy_id(data)?;

    ZoneTsigPolicyService::remove(zone_name, policy_id).await?;

    Ok(DaemonResponse {
        message: "TSIG policy deleted successfully".to_string(),
        data: serde_json::Value::Null,
    })
}

fn required_policy_id(data: &serde_json::Value) -> Result<i32, ServiceError> {
    data.get("id")
        .and_then(|v| v.as_i64())
        .and_then(|v| i32::try_from(v).ok())
        .ok_or_else(|| ServiceError::invalid_input("Missing or invalid 'id' field"))
}
