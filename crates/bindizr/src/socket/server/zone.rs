use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    record::RecordService,
    types::{
        CreateZoneRequest, ExportZoneFileResponse, GetZoneResponse, GetZonesFilter, ZoneResponse,
    },
    zone::ZoneService,
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        DaemonResponse, DiffZoneVersionsParams, ExportZoneFileParams, GetZoneParams,
        ImportZoneParams, ListZoneVersionsParams, RollbackZoneParams, UpdateZoneParams,
        ZoneNameParams, ZoneVersionParams,
    },
};

/// Return the requested zone, with its records when they were asked for.
pub(crate) async fn get_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: GetZoneParams = parse_params(data)?;

    let detail = ZoneService::get_detail(&Caller::Global, &params.name, params.records).await?;
    Ok(DaemonResponse {
        message: "Zone retrieved successfully".to_string(),
        data: to_response_data(detail)?,
    })
}

/// Return zones matching the request filters.
pub(crate) async fn list_zones(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let filter: GetZonesFilter = if data.is_null() {
        GetZonesFilter::default()
    } else {
        parse_params(data)?
    };

    let response = ZoneService::list_by_filter(&Caller::Global, filter).await?;
    Ok(DaemonResponse {
        message: "Zones retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Create a zone from the control request.
pub(crate) async fn create_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let request: CreateZoneRequest = parse_params(data)?;

    let zone = ZoneService::create(&Caller::Global, &request).await?;
    Ok(DaemonResponse {
        message: "Zone created successfully".to_string(),
        data: to_response_data(ZoneResponse {
            zone: GetZoneResponse::from_zone(&zone),
        })?,
    })
}

/// Update the requested zone.
pub(crate) async fn update_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateZoneParams = parse_params(data)?;

    let zone = ZoneService::update(&Caller::Global, &params.zone_name, &params.request).await?;
    Ok(DaemonResponse {
        message: "Zone updated successfully".to_string(),
        data: to_response_data(ZoneResponse {
            zone: GetZoneResponse::from_zone(&zone),
        })?,
    })
}

/// Preview or apply records imported into the requested zone.
pub(crate) async fn import_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ImportZoneParams = parse_params(data)?;

    let response =
        RecordService::import_zone(&Caller::Global, &params.zone_name, &params.request).await?;
    let message = if !response.errors.is_empty() {
        format!(
            "Import validation failed with {} error(s); nothing applied",
            response.errors.len()
        )
    } else if response.dry_run {
        "Dry run completed; no changes applied".to_string()
    } else {
        "Zone imported successfully".to_string()
    };

    Ok(DaemonResponse {
        message,
        data: to_response_data(response)?,
    })
}

/// Export the requested zone as a zone file.
pub(crate) async fn export_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ExportZoneFileParams = parse_params(data)?;
    let zone_file = ZoneService::export(&Caller::Global, &params.name, params.signed).await?;
    Ok(DaemonResponse {
        message: "Zone exported successfully".to_string(),
        data: to_response_data(ExportZoneFileResponse { zone_file })?,
    })
}

/// Return the requested zone's version history.
pub(crate) async fn list_zone_versions(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ListZoneVersionsParams = parse_params(data)?;

    let response = ZoneService::list_versions(
        &Caller::Global,
        &params.name,
        params.limit,
        params.offset,
        params.include_signer_serials,
    )
    .await?;

    Ok(DaemonResponse {
        message: "Versions retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Return a zone version or its difference from another version.
pub(crate) async fn get_zone_version(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneVersionParams = parse_params(data)?;

    let response = ZoneService::get_version(&Caller::Global, &params.name, params.serial).await?;

    Ok(DaemonResponse {
        message: format!("Version '{}' retrieved successfully", params.serial),
        data: to_response_data(response)?,
    })
}

/// Compare two zone versions, using the current serial when `to_serial` is omitted.
pub(crate) async fn diff_zone_versions(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DiffZoneVersionsParams = parse_params(data)?;

    let response = ZoneService::diff_versions(
        &Caller::Global,
        &params.name,
        params.from_serial,
        params.to_serial,
    )
    .await?;
    Ok(DaemonResponse {
        message: format!(
            "Serial {} -> {}: +{} -{} ~{}",
            response.from_serial,
            response.to_serial,
            response.diff.summary.added,
            response.diff.summary.removed,
            response.diff.summary.changed
        ),
        data: to_response_data(response)?,
    })
}

/// Preview or apply a rollback to the requested zone version.
pub(crate) async fn rollback_zone(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: RollbackZoneParams = parse_params(data)?;

    let response =
        ZoneService::rollback(&Caller::Global, &params.name, params.serial, params.dry_run).await?;
    let message = if response.dry_run {
        format!(
            "Dry run: rollback to serial {} would add {} and delete {} record(s); nothing applied",
            response.target_serial,
            response.summary.records_added,
            response.summary.records_deleted
        )
    } else {
        format!(
            "Zone rolled back to serial {} (new serial {})",
            response.target_serial, response.new_serial
        )
    };

    Ok(DaemonResponse {
        message,
        data: to_response_data(response)?,
    })
}

/// Return the requested zone's primary and secondary status.
pub(crate) async fn get_zone_status(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let response = ZoneService::get_status(&Caller::Global, &params.name).await?;

    let in_sync = response
        .secondaries
        .iter()
        .filter(|s| s.is_in_sync())
        .count();
    let message = if response.secondaries.is_empty() {
        "No secondaries configured".to_string()
    } else {
        format!(
            "{} of {} secondaries in sync with serial {}",
            in_sync,
            response.secondaries.len(),
            response.serial
        )
    };

    Ok(DaemonResponse {
        message,
        data: to_response_data(response)?,
    })
}

/// Delete the requested zone.
pub(crate) async fn delete_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    ZoneService::delete(&Caller::Global, &params.name).await?;
    Ok(DaemonResponse {
        message: format!("Zone '{}' deleted successfully", params.name),
        data: serde_json::Value::Null,
    })
}
