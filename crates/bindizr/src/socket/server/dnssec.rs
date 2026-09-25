use bindizr_service::{
    authorization::Caller,
    dnssec::DnssecService,
    error::ServiceError,
    types::{DnssecStatusResponse, MessageResponse},
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        DaemonResponse, DisableZoneDnssecParams, DsSeenZoneDnssecParams, EnableZoneDnssecParams,
        ImportZoneDnssecKeysParams, NameParams, RolloverZoneDnssecParams,
        UpdateZoneDnssecSettingsParams,
    },
};

/// Enable DNSSEC for the requested zone.
pub(crate) async fn enable_dnssec(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: EnableZoneDnssecParams = parse_params(data)?;

    let status = DnssecService::enable(
        &Caller::Global,
        &params.zone_name,
        params.request.policy.as_deref(),
        &params.request.parent_ns_addrs,
    )
    .await?;

    Ok(DaemonResponse {
        message: "DNSSEC enabled successfully".to_string(),
        data: to_response_data(DnssecStatusResponse { dnssec: status })?,
    })
}

/// Disable DNSSEC for the requested zone.
pub(crate) async fn disable_dnssec(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DisableZoneDnssecParams = parse_params(data)?;

    DnssecService::disable(&Caller::Global, &params.zone_name, params.skip_ds_check).await?;

    let message = "DNSSEC disabled successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Return the requested zone's DNSSEC status.
pub(crate) async fn get_dnssec_status(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    let status = DnssecService::get_status(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DNSSEC status retrieved successfully".to_string(),
        data: to_response_data(DnssecStatusResponse { dnssec: status })?,
    })
}

/// Re-sign the requested zone.
pub(crate) async fn sign_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    DnssecService::sign(&Caller::Global, &params.name).await?;

    let message = "Zone signed successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Start a DNSSEC key rollover for the requested zone.
pub(crate) async fn start_dnssec_rollover(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: RolloverZoneDnssecParams = parse_params(data)?;

    let status = DnssecService::start_rollover(
        &Caller::Global,
        &params.zone_name,
        params.request.role.as_deref(),
    )
    .await?;

    Ok(DaemonResponse {
        message: "Key rollover started successfully".to_string(),
        data: to_response_data(DnssecStatusResponse { dnssec: status })?,
    })
}

/// Confirm the parent DS and advance the requested rollover.
pub(crate) async fn ds_seen_dnssec_rollover(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DsSeenZoneDnssecParams = parse_params(data)?;

    let status = DnssecService::advance_rollover(
        &Caller::Global,
        &params.zone_name,
        params.skip_ds_check,
        params.skip_holddown,
    )
    .await?;

    Ok(DaemonResponse {
        message: "Key rollover advanced successfully".to_string(),
        data: to_response_data(DnssecStatusResponse { dnssec: status })?,
    })
}

/// Begin withdrawal of the requested zone's parent DS records.
pub(crate) async fn withdraw_dnssec(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    let status = DnssecService::withdraw(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DS withdrawal published successfully".to_string(),
        data: to_response_data(DnssecStatusResponse { dnssec: status })?,
    })
}

/// Update the requested zone's DNSSEC settings.
pub(crate) async fn update_dnssec_settings(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateZoneDnssecSettingsParams = parse_params(data)?;

    let status = DnssecService::update_settings(
        &Caller::Global,
        &params.zone_name,
        params.request.policy.as_deref(),
        params.request.parent_ns_addrs.as_deref(),
    )
    .await?;

    Ok(DaemonResponse {
        message: "DNSSEC settings changed successfully".to_string(),
        data: to_response_data(DnssecStatusResponse { dnssec: status })?,
    })
}

/// Export the requested zone's DNSSEC key files.
pub(crate) async fn export_dnssec_keys(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    let response = DnssecService::export_keys(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DNSSEC keys exported successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Import a DNSSEC key into the requested zone.
pub(crate) async fn import_dnssec_keys(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ImportZoneDnssecKeysParams = parse_params(data)?;

    let status =
        DnssecService::import_keys(&Caller::Global, &params.zone_name, params.request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC key imported successfully".to_string(),
        data: to_response_data(DnssecStatusResponse { dnssec: status })?,
    })
}

/// Cancel the requested zone's parent DS withdrawal.
pub(crate) async fn cancel_dnssec_withdrawal(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    let status = DnssecService::cancel_withdrawal(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DS withdrawal cancelled successfully".to_string(),
        data: to_response_data(DnssecStatusResponse { dnssec: status })?,
    })
}

/// Probe the parent servers for the requested zone's DS records.
pub(crate) async fn check_dnssec_ds(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    let status = DnssecService::check_ds(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "Parent DS checked successfully".to_string(),
        data: to_response_data(DnssecStatusResponse { dnssec: status })?,
    })
}
