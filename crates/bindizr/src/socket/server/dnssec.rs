use bindizr_core::model::dnssec_key::DnssecKeyRole;
use bindizr_service::{
    Context,
    authorization::Caller,
    dnssec,
    error::ServiceError,
    types::{
        DnssecStatusResponse, DsCheck, EnableDnssecRequest, ExportDnssecKeysResponse, Holddown,
        ImportDnssecKeyRequest, MessageResponse, RolloverDnssecRequest,
        UpdateDnssecSettingsRequest,
    },
};

use crate::socket::types::DaemonResponse;

/// Enable DNSSEC for the requested zone.
pub(crate) async fn enable_dnssec(
    cx: &Context,
    zone_name: &str,
    request: &EnableDnssecRequest,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let status = dnssec::enable(
        cx,
        &Caller::Global,
        zone_name,
        request.policy_name.as_deref(),
        &request.parent_ns_addrs,
    )
    .await?;
    Ok(DaemonResponse {
        message: "DNSSEC enabled successfully".to_string(),
        data: status,
    })
}

/// Disable DNSSEC for the requested zone.
pub(crate) async fn disable_dnssec(
    cx: &Context,
    zone_name: &str,
    ds_check: DsCheck,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    dnssec::disable(cx, &Caller::Global, zone_name, ds_check).await?;
    let message = "DNSSEC disabled successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Return the requested zone's DNSSEC status.
pub(crate) async fn get_dnssec_status(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let status = dnssec::get_status(cx, &Caller::Global, name).await?;
    Ok(DaemonResponse {
        message: "DNSSEC status retrieved successfully".to_string(),
        data: status,
    })
}

/// Re-sign the requested zone.
pub(crate) async fn sign_zone(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    dnssec::sign(cx, &Caller::Global, name).await?;
    let message = "Zone signed successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Start a DNSSEC key rollover for the requested zone.
pub(crate) async fn start_dnssec_rollover(
    cx: &Context,
    zone_name: &str,
    request: &RolloverDnssecRequest,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let role = request
        .role
        .as_deref()
        .map(str::parse::<DnssecKeyRole>)
        .transpose()
        .map_err(ServiceError::invalid_input)?;
    let status = dnssec::start_rollover(cx, &Caller::Global, zone_name, role).await?;
    Ok(DaemonResponse {
        message: "Key rollover started successfully".to_string(),
        data: status,
    })
}

/// Confirm the parent DS and advance the requested rollover.
pub(crate) async fn advance_dnssec_rollover(
    cx: &Context,
    zone_name: &str,
    ds_check: DsCheck,
    holddown: Holddown,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let status =
        dnssec::advance_rollover(cx, &Caller::Global, zone_name, ds_check, holddown).await?;
    Ok(DaemonResponse {
        message: "Key rollover advanced successfully".to_string(),
        data: status,
    })
}

/// Begin withdrawal of the requested zone's parent DS records.
pub(crate) async fn withdraw_dnssec(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let status = dnssec::withdraw(cx, &Caller::Global, name).await?;
    Ok(DaemonResponse {
        message: "DS withdrawal published successfully".to_string(),
        data: status,
    })
}

/// Update the requested zone's DNSSEC settings.
pub(crate) async fn update_dnssec_settings(
    cx: &Context,
    zone_name: &str,
    request: &UpdateDnssecSettingsRequest,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let status = dnssec::update_settings(
        cx,
        &Caller::Global,
        zone_name,
        request.policy_name.as_deref(),
        request.parent_ns_addrs.as_deref(),
    )
    .await?;
    Ok(DaemonResponse {
        message: "DNSSEC settings changed successfully".to_string(),
        data: status,
    })
}

/// Export the requested zone's DNSSEC key files.
pub(crate) async fn export_dnssec_keys(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<ExportDnssecKeysResponse>, ServiceError> {
    let response = dnssec::export_keys(cx, &Caller::Global, name).await?;
    Ok(DaemonResponse {
        message: "DNSSEC keys exported successfully".to_string(),
        data: response,
    })
}

/// Import a DNSSEC key into the requested zone.
pub(crate) async fn import_dnssec_keys(
    cx: &Context,
    zone_name: &str,
    request: ImportDnssecKeyRequest,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let status = dnssec::import_keys(cx, &Caller::Global, zone_name, request).await?;
    Ok(DaemonResponse {
        message: "DNSSEC key imported successfully".to_string(),
        data: status,
    })
}

/// Cancel the requested zone's parent DS withdrawal.
pub(crate) async fn cancel_dnssec_withdrawal(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let status = dnssec::cancel_withdrawal(cx, &Caller::Global, name).await?;
    Ok(DaemonResponse {
        message: "DS withdrawal cancelled successfully".to_string(),
        data: status,
    })
}

/// Probe the parent servers for the requested zone's DS records.
pub(crate) async fn check_dnssec_ds(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let status = dnssec::check_ds(cx, &Caller::Global, name).await?;
    Ok(DaemonResponse {
        message: "Parent DS checked successfully".to_string(),
        data: status,
    })
}
