use bindizr_service::{authorization::Caller, dnssec::DnssecService, error::ServiceError};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        DaemonResponse, DisableZoneDnssecParams, DsSeenZoneDnssecParams, EnableZoneDnssecParams,
        ImportZoneDnssecKeyParams, RolloverZoneDnssecParams, UpdateZoneDnssecSettingsParams,
        ZoneNameParams,
    },
};

/// Handle the `ZoneDnssecEnable` command by generating a key and signing the zone.
pub(crate) async fn enable_dnssec(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: EnableZoneDnssecParams = parse_params(data)?;

    let status = DnssecService::enable(
        &Caller::Global,
        &params.zone_name,
        params.request.policy.as_deref(),
        params.request.parent_ns_addrs.as_deref(),
    )
    .await?;

    Ok(DaemonResponse {
        message: "DNSSEC enabled successfully".to_string(),
        data: to_response_data(status)?,
    })
}

/// Handle the `ZoneDnssecDisable` command by deleting the zone's keys and
/// signatures.
pub(crate) async fn disable_dnssec(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DisableZoneDnssecParams = parse_params(data)?;

    DnssecService::disable(&Caller::Global, &params.zone_name, params.skip_ds_check).await?;

    Ok(DaemonResponse {
        message: "DNSSEC disabled successfully".to_string(),
        data: serde_json::Value::Null,
    })
}

/// Handle the `ZoneDnssecStatus` command by returning a zone's signing state.
pub(crate) async fn get_dnssec_status(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let status = DnssecService::get_status(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DNSSEC status retrieved successfully".to_string(),
        data: to_response_data(status)?,
    })
}

/// Handle the `ZoneDnssecSign` command by re-signing a zone from scratch.
pub(crate) async fn sign_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    DnssecService::sign(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "Zone signed successfully".to_string(),
        data: serde_json::Value::Null,
    })
}

/// Handle the `ZoneDnssecRolloverStart` command by pre-publishing a
/// replacement signing key.
pub(crate) async fn rollover_start(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: RolloverZoneDnssecParams = parse_params(data)?;

    let status = DnssecService::rollover_start(
        &Caller::Global,
        &params.zone_name,
        params.request.role.as_deref(),
    )
    .await?;

    Ok(DaemonResponse {
        message: "Key rollover started successfully".to_string(),
        data: to_response_data(status)?,
    })
}

/// Handle the `ZoneDnssecRolloverDsSeen` command by promoting the
/// pre-published key(s) and retiring the keys they replace.
pub(crate) async fn rollover_ds_seen(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DsSeenZoneDnssecParams = parse_params(data)?;

    let status = DnssecService::rollover_ds_seen(
        &Caller::Global,
        &params.zone_name,
        params.skip_ds_check,
        params.skip_holddown,
    )
    .await?;

    Ok(DaemonResponse {
        message: "Key rollover advanced successfully".to_string(),
        data: to_response_data(status)?,
    })
}

/// Handle the `ZoneDnssecWithdraw` command by publishing the RFC 8078 delete
/// CDS/CDNSKEY pair.
pub(crate) async fn withdraw_dnssec(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let status = DnssecService::withdraw(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DS withdrawal published successfully".to_string(),
        data: to_response_data(status)?,
    })
}

/// Handle the `ZoneDnssecUpdateSettings` command by changing the zone's
/// policy and/or parent nameservers.
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
        data: to_response_data(status)?,
    })
}

/// Handle the `ZoneDnssecKeysExport` command by returning the keys in BIND
/// file form.
pub(crate) async fn export_dnssec_keys(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let response = DnssecService::export_keys(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DNSSEC keys exported successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Handle the `ZoneDnssecKeysImport` command by importing a zone's key set
/// and signing it.
pub(crate) async fn import_dnssec_key(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ImportZoneDnssecKeyParams = parse_params(data)?;

    let status =
        DnssecService::import_keys(&Caller::Global, &params.zone_name, params.request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC key imported successfully".to_string(),
        data: to_response_data(status)?,
    })
}

/// Handle the `ZoneDnssecWithdrawCancel` command by removing the delete pair.
pub(crate) async fn cancel_dnssec_withdrawal(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let status = DnssecService::withdraw_cancel(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DS withdrawal cancelled successfully".to_string(),
        data: to_response_data(status)?,
    })
}

/// Handle the `ZoneDnssecCheckDs` command by asking the parent zone for the
/// zone's DS.
pub(crate) async fn check_dnssec_ds(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let status = DnssecService::check_ds(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "Parent DS checked successfully".to_string(),
        data: to_response_data(status)?,
    })
}
