use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    token::{TokenService, grant::TokenGrantService},
    types::{
        CreateTokenRequest, CreatedTokenResponse, GetTokenGrantResponse, GetTokenResponse,
        PageFilter, TokenGrantResponse,
    },
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        CreateTokenGrantParams, DaemonResponse, DeleteTokenGrantParams, TokenNameParams,
        ZoneNameParams,
    },
};

/// Create token from the control request.
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

/// List the requested tokens.
pub(crate) async fn list_tokens() -> Result<DaemonResponse, ServiceError> {
    let response = TokenService::list(&Caller::Global, PageFilter::default()).await?;

    Ok(DaemonResponse {
        message: "Tokens retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Delete the requested token.
pub(crate) async fn delete_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: TokenNameParams = parse_params(data)?;

    TokenService::delete(&Caller::Global, &params.name).await?;

    let response = DaemonResponse {
        message: format!("Token '{}' deleted successfully", params.name),
        data: serde_json::Value::Null,
    };
    Ok(response)
}

/// Create token grant from the control request.
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
        params.request.can_write,
    )
    .await?;

    Ok(DaemonResponse {
        message: "Token grant created successfully".to_string(),
        data: to_response_data(TokenGrantResponse {
            token_grant: GetTokenGrantResponse::from_grant(&grant),
        })?,
    })
}

/// List the requested token grants for an API token.
pub(crate) async fn list_token_grants(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: TokenNameParams = parse_params(data)?;

    let response =
        TokenGrantService::list_by_token(&Caller::Global, &params.name, PageFilter::default())
            .await?;

    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// List the requested token grants for a zone.
pub(crate) async fn list_zone_token_grants(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let response =
        TokenGrantService::list_by_zone(&Caller::Global, &params.name, PageFilter::default())
            .await?;

    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Delete the requested token grant.
pub(crate) async fn delete_token_grant(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DeleteTokenGrantParams = parse_params(data)?;

    TokenGrantService::revoke_by_id(&Caller::Global, params.id).await?;

    Ok(DaemonResponse {
        message: "Token grant revoked successfully".to_string(),
        data: serde_json::Value::Null,
    })
}
