use bindizr_service::{authorization::Caller, dnssec::DnssecService, error::ServiceError};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        DaemonResponse, DsSeenZoneDnssecParams, EnableZoneDnssecParams, RolloverZoneDnssecParams,
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
        params.request.algorithm.as_deref(),
        params.request.denial.as_deref(),
        params.request.split_keys,
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
    let params: ZoneNameParams = parse_params(data)?;

    DnssecService::disable(&Caller::Global, &params.name).await?;

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
        params.request.algorithm.as_deref(),
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

    let status =
        crate::dns::rollover::confirm_ds_seen(&Caller::Global, &params.name, params.force).await?;

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
