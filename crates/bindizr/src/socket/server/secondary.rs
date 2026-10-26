use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::types::{
    CheckSecondaryResponse, CreateSecondaryRequest, MessageResponse, PageRequest,
    PaginatedResponse, SecondaryResponse, SecondaryTransferFilter, SecondaryTransfersResponse,
    SingleSecondaryResponse, UpdateSecondaryRequest,
};
use bindizr_service::{Context, secondary};

use crate::socket::types::DaemonResponse;

/// Register a secondary from the control request.
pub(crate) async fn create_secondary(
    cx: &Context,
    request: &CreateSecondaryRequest,
) -> Result<DaemonResponse<SingleSecondaryResponse>, ServiceError> {
    let secondary = secondary::create(cx, &Caller::socket(), request).await?;
    Ok(DaemonResponse {
        message: "Secondary registered successfully".to_string(),
        data: SingleSecondaryResponse { secondary },
    })
}

/// List the requested secondaries.
pub(crate) async fn list_secondaries(
    cx: &Context,
    page: PageRequest,
) -> Result<DaemonResponse<PaginatedResponse<SecondaryResponse>>, ServiceError> {
    let response = secondary::list(cx, &Caller::socket(), page).await?;
    Ok(DaemonResponse {
        message: "Secondaries retrieved successfully".to_string(),
        data: response,
    })
}

/// Get the requested secondary.
pub(crate) async fn get_secondary(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<SingleSecondaryResponse>, ServiceError> {
    let secondary = secondary::get(cx, &Caller::socket(), name).await?;
    Ok(DaemonResponse {
        message: "Secondary retrieved successfully".to_string(),
        data: SingleSecondaryResponse { secondary },
    })
}

/// Update the requested secondary.
pub(crate) async fn update_secondary(
    cx: &Context,
    name: &str,
    request: UpdateSecondaryRequest,
) -> Result<DaemonResponse<SingleSecondaryResponse>, ServiceError> {
    let secondary = secondary::update(cx, &Caller::socket(), name, request).await?;
    Ok(DaemonResponse {
        message: "Secondary updated successfully".to_string(),
        data: SingleSecondaryResponse { secondary },
    })
}

/// Delete the requested secondary.
pub(crate) async fn delete_secondary(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    secondary::delete(cx, &Caller::socket(), name).await?;
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
) -> Result<DaemonResponse<CheckSecondaryResponse>, ServiceError> {
    let check = secondary::check(cx, &Caller::socket(), name).await?;
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
    filter: SecondaryTransferFilter,
) -> Result<DaemonResponse<SecondaryTransfersResponse>, ServiceError> {
    let transfers = secondary::list_transfers(cx, &Caller::socket(), name, filter).await?;

    Ok(DaemonResponse {
        message: format!(
            "{} transfer(s) served to secondary '{}'",
            transfers.transfers.len(),
            name
        ),
        data: transfers,
    })
}
