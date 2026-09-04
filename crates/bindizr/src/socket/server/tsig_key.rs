use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    tsig_key::{TsigKeyService, grant::TsigGrantService},
    types::{CreateTsigKeyRequest, GetTsigGrantResponse, GetTsigKeyResponse},
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        CreateTsigGrantParams, DaemonResponse, DeleteTsigGrantParams, TsigKeyNameParams,
        ZoneNameParams,
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

/// Handle the `TsigGrantCreate` command by granting a key rights in a zone.
pub(crate) async fn create_tsig_grant(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: CreateTsigGrantParams = parse_params(data)?;

    let grant = TsigGrantService::grant(
        &Caller::Global,
        &params.key_name,
        &params.request.zone_name,
        params.request.record_name_pattern.as_deref(),
        params.request.record_types.as_deref(),
    )
    .await?;

    Ok(DaemonResponse {
        message: "TSIG grant created successfully".to_string(),
        data: to_response_data(GetTsigGrantResponse::from_grant(&grant))?,
    })
}

/// Handle the `TsigGrantListByKey` command by returning a key's grants.
pub(crate) async fn list_tsig_grants_by_key(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: TsigKeyNameParams = parse_params(data)?;

    let grants = TsigGrantService::list_by_key(&Caller::Global, &params.name).await?;
    let grants: Vec<GetTsigGrantResponse> = grants
        .iter()
        .map(GetTsigGrantResponse::from_grant)
        .collect();

    Ok(DaemonResponse {
        message: "TSIG grants retrieved successfully".to_string(),
        data: to_response_data(grants)?,
    })
}

/// Handle the `TsigGrantListByZone` command by returning the grants that
/// apply to a zone.
pub(crate) async fn list_tsig_grants_by_zone(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let grants = TsigGrantService::list_by_zone(&Caller::Global, &params.name).await?;
    let grants: Vec<GetTsigGrantResponse> = grants
        .iter()
        .map(GetTsigGrantResponse::from_grant)
        .collect();

    Ok(DaemonResponse {
        message: "TSIG grants retrieved successfully".to_string(),
        data: to_response_data(grants)?,
    })
}

/// Handle the `TsigGrantDelete` command by revoking one of a key's grants.
pub(crate) async fn delete_tsig_grant(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DeleteTsigGrantParams = parse_params(data)?;

    TsigGrantService::revoke(&Caller::Global, &params.key_name, params.id).await?;

    Ok(DaemonResponse {
        message: "TSIG grant revoked successfully".to_string(),
        data: serde_json::Value::Null,
    })
}
