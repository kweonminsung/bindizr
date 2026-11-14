use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::types::{
    DnssecStatusResponse, DsCheck, EnableDnssecRequest, ExportDnssecKeysResponse, Holddown,
    ImportDnssecKeysRequest, MessageResponse, StartDnssecRolloverRequest,
    UpdateDnssecSettingsRequest,
};
use bindizr_service::{Context, dnssec, zone};

use crate::socket::types::DaemonResponse;

/// Enable DNSSEC for the requested zone.
pub(crate) async fn enable_dnssec(
    cx: &Context,
    zone_name: &str,
    request: &EnableDnssecRequest,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let response = dnssec::enable(
        cx,
        &Caller::socket(),
        &zone::normalize_name(zone_name)?,
        request,
    )
    .await?;

    Ok(DaemonResponse {
        message: "DNSSEC enabled successfully".to_string(),
        data: response,
    })
}

/// Disable DNSSEC for the requested zone.
pub(crate) async fn disable_dnssec(
    cx: &Context,
    zone_name: &str,
    ds_check: DsCheck,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    dnssec::disable(
        cx,
        &Caller::socket(),
        &zone::normalize_name(zone_name)?,
        ds_check,
    )
    .await?;

    let message = "DNSSEC disabled successfully".to_string();

    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Get the requested zone's DNSSEC status.
pub(crate) async fn get_dnssec_status(
    cx: &Context,
    zone_name: &str,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let response =
        dnssec::get_status(cx, &Caller::socket(), &zone::normalize_name(zone_name)?).await?;
    Ok(DaemonResponse {
        message: "DNSSEC status retrieved successfully".to_string(),
        data: response,
    })
}

/// Re-sign the requested zone.
pub(crate) async fn sign_zone(
    cx: &Context,
    zone_name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    dnssec::sign(cx, &Caller::socket(), &zone::normalize_name(zone_name)?).await?;
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
    request: &StartDnssecRolloverRequest,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let response = dnssec::start_rollover(
        cx,
        &Caller::socket(),
        &zone::normalize_name(zone_name)?,
        request,
    )
    .await?;

    Ok(DaemonResponse {
        message: "Key rollover started successfully".to_string(),
        data: response,
    })
}

/// Confirm the parent DS and advance the requested rollover.
pub(crate) async fn advance_dnssec_rollover(
    cx: &Context,
    zone_name: &str,
    ds_check: DsCheck,
    holddown: Holddown,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let response = dnssec::advance_rollover(
        cx,
        &Caller::socket(),
        &zone::normalize_name(zone_name)?,
        ds_check,
        holddown,
    )
    .await?;

    Ok(DaemonResponse {
        message: "Key rollover advanced successfully".to_string(),
        data: response,
    })
}

/// Begin withdrawal of the requested zone's parent DS records.
pub(crate) async fn withdraw_dnssec(
    cx: &Context,
    zone_name: &str,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let response =
        dnssec::withdraw(cx, &Caller::socket(), &zone::normalize_name(zone_name)?).await?;
    Ok(DaemonResponse {
        message: "DS withdrawal published successfully".to_string(),
        data: response,
    })
}

/// Update the requested zone's DNSSEC settings.
pub(crate) async fn update_dnssec_settings(
    cx: &Context,
    zone_name: &str,
    request: &UpdateDnssecSettingsRequest,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let response = dnssec::update_settings(
        cx,
        &Caller::socket(),
        &zone::normalize_name(zone_name)?,
        request,
    )
    .await?;

    Ok(DaemonResponse {
        message: "DNSSEC settings changed successfully".to_string(),
        data: response,
    })
}

/// Export the requested zone's DNSSEC key files.
pub(crate) async fn export_dnssec_keys(
    cx: &Context,
    zone_name: &str,
) -> Result<DaemonResponse<ExportDnssecKeysResponse>, ServiceError> {
    let response =
        dnssec::export_keys(cx, &Caller::socket(), &zone::normalize_name(zone_name)?).await?;
    Ok(DaemonResponse {
        message: "DNSSEC keys exported successfully".to_string(),
        data: response,
    })
}

/// Import a DNSSEC key into the requested zone.
pub(crate) async fn import_dnssec_keys(
    cx: &Context,
    zone_name: &str,
    request: ImportDnssecKeysRequest,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let response = dnssec::import_keys(
        cx,
        &Caller::socket(),
        &zone::normalize_name(zone_name)?,
        request,
    )
    .await?;

    Ok(DaemonResponse {
        message: "DNSSEC key imported successfully".to_string(),
        data: response,
    })
}

/// Cancel the requested zone's parent DS withdrawal.
pub(crate) async fn cancel_dnssec_withdrawal(
    cx: &Context,
    zone_name: &str,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let response =
        dnssec::cancel_withdrawal(cx, &Caller::socket(), &zone::normalize_name(zone_name)?).await?;
    Ok(DaemonResponse {
        message: "DS withdrawal cancelled successfully".to_string(),
        data: response,
    })
}

/// Probe the parent servers for the requested zone's DS records.
pub(crate) async fn check_dnssec_ds(
    cx: &Context,
    zone_name: &str,
) -> Result<DaemonResponse<DnssecStatusResponse>, ServiceError> {
    let response =
        dnssec::check_ds(cx, &Caller::socket(), &zone::normalize_name(zone_name)?).await?;
    Ok(DaemonResponse {
        message: "Parent DS checked successfully".to_string(),
        data: response,
    })
}
