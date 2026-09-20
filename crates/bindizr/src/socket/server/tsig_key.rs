use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    tsig_key::{TsigKeyService, grant::TsigGrantService},
    types::{
        CreateTsigKeyRequest, GetTsigGrantResponse, MessageResponse, PageFilter, TsigGrantResponse,
        TsigKeyResponse,
    },
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        CreateTsigGrantParams, DaemonResponse, DeleteTsigGrantParams,
        DeleteTsigGrantsByKeyAndZoneParams, ListGrantsParams, TsigKeyNameParams,
    },
};

/// Create TSIG key from the control request.
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
        data: to_response_data(TsigKeyResponse::from_key(&key))?,
    })
}

/// List the requested TSIG keys.
pub(crate) async fn list_tsig_keys(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let page: PageFilter = parse_params(data)?;

    let response = TsigKeyService::list(&Caller::Global, page).await?;

    Ok(DaemonResponse {
        message: "TSIG keys retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Get the requested TSIG key.
pub(crate) async fn get_tsig_key(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: TsigKeyNameParams = parse_params(data)?;

    let key = TsigKeyService::get(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "TSIG key retrieved successfully".to_string(),
        data: to_response_data(TsigKeyResponse::from_key(&key))?,
    })
}

/// Delete the requested TSIG key.
pub(crate) async fn delete_tsig_key(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: TsigKeyNameParams = parse_params(data)?;

    TsigKeyService::delete(&Caller::Global, &params.name).await?;

    let message = format!("TSIG key '{}' deleted successfully", params.name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Create TSIG grant from the control request.
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
        params.request.can_write,
    )
    .await?;

    Ok(DaemonResponse {
        message: "TSIG grant created successfully".to_string(),
        data: to_response_data(TsigGrantResponse {
            tsig_grant: GetTsigGrantResponse::from_grant(&grant),
        })?,
    })
}

/// List the requested TSIG grants for a TSIG key.
pub(crate) async fn list_tsig_grants(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ListGrantsParams = parse_params(data)?;

    let response =
        TsigGrantService::list_by_key(&Caller::Global, &params.name, params.page).await?;

    Ok(DaemonResponse {
        message: "TSIG grants retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// List the requested TSIG grants for a zone.
pub(crate) async fn list_zone_tsig_grants(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ListGrantsParams = parse_params(data)?;

    let response =
        TsigGrantService::list_by_zone(&Caller::Global, &params.name, params.page).await?;

    Ok(DaemonResponse {
        message: "TSIG grants retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Delete the requested TSIG grant.
pub(crate) async fn delete_tsig_grant(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DeleteTsigGrantParams = parse_params(data)?;

    TsigGrantService::revoke_by_id(&Caller::Global, params.id).await?;

    let message = "TSIG grant revoked successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Revoke every grant the requested TSIG key holds in the requested zone.
pub(crate) async fn delete_tsig_grants_by_key_and_zone(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DeleteTsigGrantsByKeyAndZoneParams = parse_params(data)?;

    let revoked = TsigGrantService::revoke_by_key_and_zone(
        &Caller::Global,
        &params.key_name,
        &params.zone_name,
    )
    .await?;

    let message = format!("{} TSIG grant(s) revoked successfully", revoked);
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}
