use bindizr_service::{
    error::ServiceError, tsig_key::TsigKeyService, zone::tsig_policy::ZoneTsigPolicyService,
};
use serde::Deserialize;

use crate::{
    api::types::{
        CreateTsigKeyRequest, CreateZoneTsigPolicyRequest, GetTsigKeyResponse,
        GetZoneTsigPolicyResponse,
    },
    socket::{server::parse_params, types::DaemonResponse},
};

#[derive(Deserialize)]
struct TsigKeyNameParams {
    name: String,
}

#[derive(Deserialize)]
struct ZoneNameParams {
    zone_name: String,
}

#[derive(Deserialize)]
struct AddZoneTsigPolicyParams {
    zone_name: String,
    #[serde(flatten)]
    request: CreateZoneTsigPolicyRequest,
}

#[derive(Deserialize)]
struct RemoveZoneTsigPolicyParams {
    zone_name: String,
    id: i32,
}

fn to_response_data<T: serde::Serialize>(value: T) -> Result<serde_json::Value, ServiceError> {
    serde_json::to_value(value)
        .map_err(|e| ServiceError::internal(format!("Failed to serialize response: {}", e)))
}

/// Handle the `TsigKeyCreate` command by creating (or importing) a TSIG key.
pub(super) async fn create_tsig_key(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateTsigKeyRequest = parse_params(data)?;

    let key = TsigKeyService::create(
        &request.name,
        request.algorithm.as_deref(),
        request.secret.as_deref(),
        request.global,
    )
    .await?;

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
    let params: TsigKeyNameParams = parse_params(data)?;

    let key = TsigKeyService::get(&params.name).await?;

    Ok(DaemonResponse {
        message: "TSIG key retrieved successfully".to_string(),
        data: to_response_data(GetTsigKeyResponse::from_key(&key))?,
    })
}

/// Handle the `TsigKeyDelete` command by deleting an unused TSIG key.
pub(super) async fn delete_tsig_key(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: TsigKeyNameParams = parse_params(data)?;

    TsigKeyService::delete(&params.name).await?;

    Ok(DaemonResponse {
        message: "TSIG key deleted successfully".to_string(),
        data: serde_json::Value::Null,
    })
}

/// Handle the `ZoneTsigPolicyAdd` command by granting a key rights in a zone.
pub(super) async fn add_zone_tsig_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: AddZoneTsigPolicyParams = parse_params(data)?;

    let policy = ZoneTsigPolicyService::add(
        &params.zone_name,
        &params.request.tsig_key,
        params.request.record_name_pattern.as_deref(),
        params.request.record_types.as_deref(),
    )
    .await?;

    Ok(DaemonResponse {
        message: "TSIG policy created successfully".to_string(),
        data: to_response_data(GetZoneTsigPolicyResponse::from_policy(&policy))?,
    })
}

/// Handle the `ZoneTsigPolicyList` command by returning a zone's policies.
pub(super) async fn list_zone_tsig_policies(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let policies = ZoneTsigPolicyService::list(&params.zone_name).await?;
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
    let params: RemoveZoneTsigPolicyParams = parse_params(data)?;

    ZoneTsigPolicyService::remove(&params.zone_name, params.id).await?;

    Ok(DaemonResponse {
        message: "TSIG policy deleted successfully".to_string(),
        data: serde_json::Value::Null,
    })
}
