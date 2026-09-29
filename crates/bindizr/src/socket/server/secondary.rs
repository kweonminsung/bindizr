use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    secondary,
    types::{
        CreateSecondaryRequest, GetSecondaryResponse, GetSecondaryTransfersFilter, MessageResponse,
        PageFilter, PaginatedResponse, SecondaryCheckResponse, SecondaryResponse,
        SecondaryTransfersResponse, UpdateSecondaryRequest,
    },
};

use crate::socket::types::DaemonResponse;

/// Register a secondary from the control request.
pub(crate) async fn create_secondary(
    cx: &Context,
    request: &CreateSecondaryRequest,
) -> Result<DaemonResponse<SecondaryResponse>, ServiceError> {
    let secondary = secondary::create(
        cx,
        &Caller::Global,
        &request.name,
        &request.address,
        request.notify_key_name.as_deref(),
    )
    .await?;
    Ok(DaemonResponse {
        message: "Secondary registered successfully".to_string(),
        data: SecondaryResponse { secondary },
    })
}

/// List the requested secondaries.
pub(crate) async fn list_secondaries(
    cx: &Context,
    page: PageFilter,
) -> Result<DaemonResponse<PaginatedResponse<GetSecondaryResponse>>, ServiceError> {
    let response = secondary::list(cx, &Caller::Global, page).await?;
    Ok(DaemonResponse {
        message: "Secondaries retrieved successfully".to_string(),
        data: response,
    })
}

/// Get the requested secondary.
pub(crate) async fn get_secondary(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<SecondaryResponse>, ServiceError> {
    let secondary = secondary::get(cx, &Caller::Global, name).await?;
    Ok(DaemonResponse {
        message: "Secondary retrieved successfully".to_string(),
        data: SecondaryResponse { secondary },
    })
}

/// Update the requested secondary.
pub(crate) async fn update_secondary(
    cx: &Context,
    name: &str,
    request: UpdateSecondaryRequest,
) -> Result<DaemonResponse<SecondaryResponse>, ServiceError> {
    let secondary = secondary::update(cx, &Caller::Global, name, request).await?;
    Ok(DaemonResponse {
        message: "Secondary updated successfully".to_string(),
        data: SecondaryResponse { secondary },
    })
}

/// Delete the requested secondary.
pub(crate) async fn delete_secondary(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    secondary::delete(cx, &Caller::Global, name).await?;
    let message = format!("Secondary '{}' deleted successfully", name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Check the requested secondary: resolution, catalog serial, and NOTIFY.
pub(crate) async fn check_secondary(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<SecondaryCheckResponse>, ServiceError> {
    let check = secondary::check(cx, &Caller::Global, name).await?;
    let message = if check.is_healthy() {
        format!("Secondary '{}' passed the check", name)
    } else {
        format!("Secondary '{}' failed the check", name)
    };
    Ok(DaemonResponse {
        message,
        data: check,
    })
}

/// The transfers Bindizr served one secondary.
pub(crate) async fn list_secondary_transfers(
    cx: &Context,
    name: &str,
    filter: GetSecondaryTransfersFilter,
) -> Result<DaemonResponse<SecondaryTransfersResponse>, ServiceError> {
    let transfers = secondary::list_transfers(cx, &Caller::Global, name, filter).await?;
    Ok(DaemonResponse {
        message: format!(
            "{} transfer(s) served to secondary '{}'",
            transfers.transfers.len(),
            name
        ),
        data: transfers,
    })
}
