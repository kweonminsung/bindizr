use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    secondary::SecondaryService,
    types::{CreateSecondaryRequest, MessageResponse, PageFilter, SecondaryResponse},
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{DaemonResponse, NameParams, UpdateSecondaryParams},
};

/// Register a secondary from the control request.
pub(crate) async fn create_secondary(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateSecondaryRequest = parse_params(data)?;
    let secondary = SecondaryService::create(
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
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let page: PageFilter = parse_params(data)?;
    let response = SecondaryService::list(&Caller::Global, page).await?;

    Ok(DaemonResponse {
        message: "Secondaries retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Get the requested secondary.
pub(crate) async fn get_secondary(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;
    let secondary = SecondaryService::get(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "Secondary retrieved successfully".to_string(),
        data: to_response_data(SecondaryResponse { secondary })?,
    })
}

/// Update the requested secondary.
pub(crate) async fn update_secondary(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateSecondaryParams = parse_params(data)?;
    let secondary = SecondaryService::update(&Caller::Global, &params.name, params.request).await?;

    Ok(DaemonResponse {
        message: "Secondary updated successfully".to_string(),
        data: to_response_data(SecondaryResponse { secondary })?,
    })
}

/// Delete the requested secondary.
pub(crate) async fn delete_secondary(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;
    SecondaryService::delete(&Caller::Global, &params.name).await?;

    let message = format!("Secondary '{}' deleted successfully", params.name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Check the requested secondary: resolution, catalog serial, and NOTIFY.
pub(crate) async fn check_secondary(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;
    let check = SecondaryService::check(&Caller::Global, &params.name).await?;

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
