use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    secondary,
    types::{CreateSecondaryRequest, MessageResponse, PageFilter, SecondaryResponse},
};

use crate::{
    params::NameParams,
    socket::{
        server::{parse_params, to_response_data},
        types::{DaemonResponse, ListSecondaryTransfersParams, UpdateSecondaryParams},
    },
};

/// Register a secondary from the control request.
pub(crate) async fn create_secondary(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateSecondaryRequest = parse_params(data)?;
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
        data: to_response_data(SecondaryResponse { secondary })?,
    })
}

/// List the requested secondaries.
pub(crate) async fn list_secondaries(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let page: PageFilter = parse_params(data)?;
    let response = secondary::list(cx, &Caller::Global, page).await?;

    Ok(DaemonResponse {
        message: "Secondaries retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Get the requested secondary.
pub(crate) async fn get_secondary(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;
    let secondary = secondary::get(cx, &Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "Secondary retrieved successfully".to_string(),
        data: to_response_data(SecondaryResponse { secondary })?,
    })
}

/// Update the requested secondary.
pub(crate) async fn update_secondary(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateSecondaryParams = parse_params(data)?;
    let secondary = secondary::update(cx, &Caller::Global, &params.name, params.request).await?;

    Ok(DaemonResponse {
        message: "Secondary updated successfully".to_string(),
        data: to_response_data(SecondaryResponse { secondary })?,
    })
}

/// Delete the requested secondary.
pub(crate) async fn delete_secondary(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;
    secondary::delete(cx, &Caller::Global, &params.name).await?;

    let message = format!("Secondary '{}' deleted successfully", params.name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Check the requested secondary: resolution, catalog serial, and NOTIFY.
pub(crate) async fn check_secondary(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;
    let check = secondary::check(cx, &Caller::Global, &params.name).await?;

    let message = if check.is_healthy() {
        format!("Secondary '{}' passed the check", params.name)
    } else {
        format!("Secondary '{}' failed the check", params.name)
    };
    Ok(DaemonResponse {
        message,
        data: to_response_data(check)?,
    })
}

/// The transfers Bindizr served one secondary.
pub(crate) async fn list_secondary_transfers(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ListSecondaryTransfersParams = parse_params(data)?;
    let transfers =
        secondary::list_transfers(cx, &Caller::Global, &params.name, params.filter).await?;
    Ok(DaemonResponse {
        message: format!(
            "{} transfer(s) served to secondary '{}'",
            transfers.transfers.len(),
            params.name
        ),
        data: to_response_data(transfers)?,
    })
}
