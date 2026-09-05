use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    token::{TokenService, grant::TokenGrantService},
    types::{CreateTokenRequest, CreatedTokenResponse, GetTokenGrantResponse, GetTokenResponse},
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        CreateTokenGrantParams, DaemonResponse, DeleteTokenGrantParams, TokenNameParams,
        ZoneNameParams,
    },
};

/// Handle the `TokenCreate` command by creating a new API token.
pub(crate) async fn create_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let request: CreateTokenRequest = parse_params(data)?;

    let (token, secret) = TokenService::create(
        &Caller::Global,
        &request.name,
        request.description.as_deref(),
        request.expires_in_days,
        request.global,
    )
    .await?;

    let response = DaemonResponse {
        message: "Token created successfully".to_string(),
        data: to_response_data(CreatedTokenResponse {
            token: GetTokenResponse::from_token(&token),
            secret,
        })?,
    };
    Ok(response)
}

/// Handle the `TokenList` command by returning all API tokens.
pub(crate) async fn list_tokens() -> Result<DaemonResponse, ServiceError> {
    let tokens = TokenService::list(&Caller::Global).await?;
    let tokens: Vec<GetTokenResponse> = tokens.iter().map(GetTokenResponse::from_token).collect();

    let response = DaemonResponse {
        message: "Tokens retrieved successfully".to_string(),
        data: to_response_data(tokens)?,
    };
    Ok(response)
}

/// Handle the `TokenDelete` command by deleting an API token by name.
pub(crate) async fn delete_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: TokenNameParams = parse_params(data)?;

    TokenService::delete(&Caller::Global, &params.name).await?;

    let response = DaemonResponse {
        message: "Token deleted successfully".to_string(),
        data: serde_json::Value::Null,
    };
    Ok(response)
}

/// Handle the `TokenGrantCreate` command by granting a token rights in a zone.
pub(crate) async fn create_token_grant(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: CreateTokenGrantParams = parse_params(data)?;

    let grant = TokenGrantService::grant(
        &Caller::Global,
        &params.token_name,
        &params.request.zone_name,
        params.request.record_name_pattern.as_deref(),
        params.request.record_types.as_deref(),
    )
    .await?;

    Ok(DaemonResponse {
        message: "Token grant created successfully".to_string(),
        data: to_response_data(GetTokenGrantResponse::from_grant(&grant))?,
    })
}

/// Handle the `TokenGrantListByToken` command by returning a token's grants.
pub(crate) async fn list_token_grants_by_token(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: TokenNameParams = parse_params(data)?;

    let grants = TokenGrantService::list_by_token(&Caller::Global, &params.name).await?;
    let grants: Vec<GetTokenGrantResponse> = grants
        .iter()
        .map(GetTokenGrantResponse::from_grant)
        .collect();

    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: to_response_data(grants)?,
    })
}

/// Handle the `TokenGrantListByZone` command by returning the grants that
/// apply to a zone.
pub(crate) async fn list_token_grants_by_zone(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let grants = TokenGrantService::list_by_zone(&Caller::Global, &params.name).await?;
    let grants: Vec<GetTokenGrantResponse> = grants
        .iter()
        .map(GetTokenGrantResponse::from_grant)
        .collect();

    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: to_response_data(grants)?,
    })
}

/// Handle the `TokenGrantDelete` command by revoking one of a token's grants.
pub(crate) async fn delete_token_grant(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DeleteTokenGrantParams = parse_params(data)?;

    TokenGrantService::revoke(&Caller::Global, &params.token_name, params.id).await?;

    Ok(DaemonResponse {
        message: "Token grant revoked successfully".to_string(),
        data: serde_json::Value::Null,
    })
}
