use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    token::TokenService,
    types::{GetTokenResponse, GetZoneTokenPolicyResponse},
    zone::token_policy::ZoneTokenPolicyService,
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        AddZoneTokenPolicyParams, CreateTokenParams, DaemonResponse, RemoveZonePolicyParams,
        TokenNameParams, ZonePolicyListParams,
    },
};

/// Handle the `TokenCreate` command by creating a new API token.
pub(super) async fn create_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: CreateTokenParams = parse_params(data)?;

    let created_token = TokenService::create(
        &Caller::Global,
        &params.name,
        params.description.as_deref(),
        params.expires_in_days,
        params.global,
    )
    .await?;

    let response = DaemonResponse {
        message: "Token created successfully".to_string(),
        data: to_response_data(GetTokenResponse::from_token(&created_token))?,
    };
    Ok(response)
}

/// Handle the `TokenList` command by returning all API tokens.
pub(super) async fn list_tokens() -> Result<DaemonResponse, ServiceError> {
    let tokens = TokenService::list(&Caller::Global).await?;
    let tokens: Vec<GetTokenResponse> = tokens.iter().map(GetTokenResponse::from_token).collect();

    let response = DaemonResponse {
        message: "Tokens retrieved successfully".to_string(),
        data: to_response_data(tokens)?,
    };
    Ok(response)
}

/// Handle the `TokenDelete` command by deleting an API token by name.
pub(super) async fn delete_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: TokenNameParams = parse_params(data)?;

    TokenService::delete(&Caller::Global, &params.name).await?;

    let response = DaemonResponse {
        message: "Token deleted successfully".to_string(),
        data: serde_json::Value::Null,
    };
    Ok(response)
}

/// Handle the `ZoneTokenPolicyAdd` command by granting a token rights in a zone.
pub(super) async fn add_zone_token_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: AddZoneTokenPolicyParams = parse_params(data)?;

    let policy = ZoneTokenPolicyService::add(
        &Caller::Global,
        &params.zone_name,
        &params.request.api_token,
        params.request.record_name_pattern.as_deref(),
        params.request.record_types.as_deref(),
    )
    .await?;

    Ok(DaemonResponse {
        message: "Token policy created successfully".to_string(),
        data: to_response_data(GetZoneTokenPolicyResponse::from_policy(&policy))?,
    })
}

/// Handle the `ZoneTokenPolicyList` command by returning a zone's policies.
pub(super) async fn list_zone_token_policies(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZonePolicyListParams = parse_params(data)?;

    let policies = ZoneTokenPolicyService::list(&Caller::Global, &params.zone_name).await?;
    let policies: Vec<GetZoneTokenPolicyResponse> = policies
        .iter()
        .map(GetZoneTokenPolicyResponse::from_policy)
        .collect();

    Ok(DaemonResponse {
        message: "Token policies retrieved successfully".to_string(),
        data: to_response_data(policies)?,
    })
}

/// Handle the `ZoneTokenPolicyRemove` command by removing one policy of a zone.
pub(super) async fn remove_zone_token_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: RemoveZonePolicyParams = parse_params(data)?;

    ZoneTokenPolicyService::remove(&Caller::Global, &params.zone_name, params.id).await?;

    Ok(DaemonResponse {
        message: "Token policy deleted successfully".to_string(),
        data: serde_json::Value::Null,
    })
}
