use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    tsig_key::TsigKeyService,
    types::{CreateTsigKeyRequest, GetTsigKeyResponse, GetZoneTsigPolicyResponse},
    zone::tsig_policy::ZoneTsigPolicyService,
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        AddZoneTsigPolicyParams, DaemonResponse, RemoveZonePolicyParams, TsigKeyNameParams,
        ZonePolicyListParams,
    },
};

/// Handle the `TsigKeyCreate` command by creating (or importing) a TSIG key.
pub(crate) async fn create_tsig_key(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateTsigKeyRequest = parse_params(data)?;

    let key = TsigKeyService::create(
        &Caller::Global,
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
pub(crate) async fn list_tsig_keys() -> Result<DaemonResponse, ServiceError> {
    let keys = TsigKeyService::list(&Caller::Global).await?;
    let keys: Vec<GetTsigKeyResponse> = keys.iter().map(GetTsigKeyResponse::from_key).collect();

    Ok(DaemonResponse {
        message: "TSIG keys retrieved successfully".to_string(),
        data: to_response_data(keys)?,
    })
}

/// Handle the `TsigKeyGet` command by returning one TSIG key with its secret.
pub(crate) async fn get_tsig_key(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: TsigKeyNameParams = parse_params(data)?;

    let key = TsigKeyService::get(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "TSIG key retrieved successfully".to_string(),
        data: to_response_data(GetTsigKeyResponse::from_key(&key))?,
    })
}

/// Handle the `TsigKeyDelete` command by deleting an unused TSIG key.
pub(crate) async fn delete_tsig_key(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: TsigKeyNameParams = parse_params(data)?;

    TsigKeyService::delete(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "TSIG key deleted successfully".to_string(),
        data: serde_json::Value::Null,
    })
}

/// Handle the `ZoneTsigPolicyAdd` command by granting a key rights in a zone.
pub(crate) async fn add_zone_tsig_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: AddZoneTsigPolicyParams = parse_params(data)?;

    let policy = ZoneTsigPolicyService::add(
        &Caller::Global,
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
pub(crate) async fn list_zone_tsig_policies(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZonePolicyListParams = parse_params(data)?;

    let policies = ZoneTsigPolicyService::list(&Caller::Global, &params.zone_name).await?;
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
pub(crate) async fn remove_zone_tsig_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: RemoveZonePolicyParams = parse_params(data)?;

    ZoneTsigPolicyService::remove(&Caller::Global, &params.zone_name, params.id).await?;

    Ok(DaemonResponse {
        message: "TSIG policy deleted successfully".to_string(),
        data: serde_json::Value::Null,
    })
}
