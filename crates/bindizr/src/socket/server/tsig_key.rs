use bindizr_core::model::tsig_grant::TsigGrantId;
use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    tsig_key::{self, grant},
    types::{
        CreateGrantRequest, CreateTsigKeyRequest, GetTsigGrantResponse, GetTsigKeyResponse,
        MessageResponse, PageFilter, PaginatedResponse, TsigGrantResponse, TsigKeyResponse,
    },
    zone,
};

use crate::socket::types::DaemonResponse;

/// Create TSIG key from the control request.
pub(crate) async fn create_tsig_key(
    cx: &Context,
    request: &CreateTsigKeyRequest,
) -> Result<DaemonResponse<TsigKeyResponse>, ServiceError> {
    let key = tsig_key::create(cx, &Caller::Global, request).await?;
    Ok(DaemonResponse {
        message: "TSIG key created successfully".to_string(),
        data: TsigKeyResponse::from(&key),
    })
}

/// List the requested TSIG keys.
pub(crate) async fn list_tsig_keys(
    cx: &Context,
    page: PageFilter,
) -> Result<DaemonResponse<PaginatedResponse<GetTsigKeyResponse>>, ServiceError> {
    let response = tsig_key::list(cx, &Caller::Global, page).await?;
    Ok(DaemonResponse {
        message: "TSIG keys retrieved successfully".to_string(),
        data: response,
    })
}

/// Get the requested TSIG key.
pub(crate) async fn get_tsig_key(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<TsigKeyResponse>, ServiceError> {
    let key = tsig_key::get(cx, &Caller::Global, name).await?;
    Ok(DaemonResponse {
        message: "TSIG key retrieved successfully".to_string(),
        data: TsigKeyResponse::from(&key),
    })
}

/// Delete the requested TSIG key.
pub(crate) async fn delete_tsig_key(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    tsig_key::delete(cx, &Caller::Global, name).await?;
    let message = format!("TSIG key '{}' deleted successfully", name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Create TSIG grant from the control request.
pub(crate) async fn create_tsig_grant(
    cx: &Context,
    key_name: &str,
    request: &CreateGrantRequest,
) -> Result<DaemonResponse<TsigGrantResponse>, ServiceError> {
    let grant = grant::create(cx, &Caller::Global, key_name, request).await?;
    Ok(DaemonResponse {
        message: "TSIG grant created successfully".to_string(),
        data: TsigGrantResponse {
            tsig_grant: GetTsigGrantResponse::from(&grant),
        },
    })
}

/// List the requested TSIG grants for a TSIG key.
pub(crate) async fn list_tsig_grants(
    cx: &Context,
    key_name: &str,
    page: PageFilter,
) -> Result<DaemonResponse<PaginatedResponse<GetTsigGrantResponse>>, ServiceError> {
    let response = grant::list_by_key(cx, &Caller::Global, key_name, page).await?;
    Ok(DaemonResponse {
        message: "TSIG grants retrieved successfully".to_string(),
        data: response,
    })
}

/// List the requested TSIG grants for a zone.
pub(crate) async fn list_zone_tsig_grants(
    cx: &Context,
    zone_name: &str,
    page: PageFilter,
) -> Result<DaemonResponse<PaginatedResponse<GetTsigGrantResponse>>, ServiceError> {
    let response =
        grant::list_by_zone(cx, &Caller::Global, &zone::normalize_name(zone_name)?, page).await?;
    Ok(DaemonResponse {
        message: "TSIG grants retrieved successfully".to_string(),
        data: response,
    })
}

/// Delete the requested TSIG grant.
pub(crate) async fn delete_tsig_grant(
    cx: &Context,
    id: TsigGrantId,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    grant::revoke_by_id(cx, &Caller::Global, id).await?;
    let message = "TSIG grant revoked successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Revoke every grant the requested TSIG key holds in the requested zone.
pub(crate) async fn delete_tsig_grants_by_key_and_zone(
    cx: &Context,
    key_name: &str,
    zone_name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let revoked = grant::revoke_by_key_and_zone(
        cx,
        &Caller::Global,
        key_name,
        &zone::normalize_name(zone_name)?,
    )
    .await?;
    let message = format!("{} TSIG grant(s) revoked successfully", revoked);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}
