use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    tsig_key,
    types::{
        CreateTsigKeyRequest, MessageResponse, PaginatedResponse, SingleTsigKeyResponse,
        TsigKeyFilter, TsigKeyResponse,
    },
};

use crate::socket::types::DaemonResponse;

/// Create TSIG key from the control request.
pub(crate) async fn create_tsig_key(
    cx: &Context,
    request: &CreateTsigKeyRequest,
) -> Result<DaemonResponse<SingleTsigKeyResponse>, ServiceError> {
    let data = tsig_key::create(cx, &Caller::socket(), request).await?;
    Ok(DaemonResponse {
        message: "TSIG key created successfully".to_string(),
        data,
    })
}

/// List the requested TSIG keys.
pub(crate) async fn list_tsig_keys(
    cx: &Context,
    filter: &TsigKeyFilter,
) -> Result<DaemonResponse<PaginatedResponse<TsigKeyResponse>>, ServiceError> {
    let response = tsig_key::list(cx, &Caller::socket(), filter).await?;
    Ok(DaemonResponse {
        message: "TSIG keys retrieved successfully".to_string(),
        data: response,
    })
}

/// Get the requested TSIG key.
pub(crate) async fn get_tsig_key(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<SingleTsigKeyResponse>, ServiceError> {
    let data = tsig_key::get(cx, &Caller::socket(), name).await?;
    Ok(DaemonResponse {
        message: "TSIG key retrieved successfully".to_string(),
        data,
    })
}

/// Delete the requested TSIG key.
pub(crate) async fn delete_tsig_key(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    tsig_key::delete(cx, &Caller::socket(), name).await?;
    let message = format!("TSIG key '{}' deleted successfully", name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}
