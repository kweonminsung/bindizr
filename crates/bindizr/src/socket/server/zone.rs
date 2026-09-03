use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    record::RecordService,
    types::{
        CreateZoneRequest, ExportZoneFileResponse, GetZoneResponse, GetZonesFilter,
        ImportZoneFileResponse,
    },
    zone::ZoneService,
};
use serde_json::json;

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        DaemonResponse, DiffZoneVersionsParams, ExportZoneFileParams, ImportZoneFileParams,
        ImportZoneFromServerParams, ListZoneVersionsParams, RollbackZoneParams, UpdateZoneParams,
        ZoneNameParams, ZoneVersionParams,
    },
};

/// Handle the `GetZone` command by returning a zone by name.
pub(crate) async fn get_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let zone = ZoneService::get_by_name(&Caller::Global, &params.name).await?;
    Ok(DaemonResponse {
        message: "Zone retrieved successfully".to_string(),
        data: to_response_data(GetZoneResponse::from_zone(&zone))?,
    })
}

/// Handle the `ListZones` command by returning zones matching the filter.
pub(crate) async fn list_zones(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let filter: GetZonesFilter = if data.is_null() {
        GetZonesFilter::default()
    } else {
        parse_params(data)?
    };

    let response = ZoneService::list_by_filter(&Caller::Global, filter).await?;
    Ok(DaemonResponse {
        message: format!("Found {} zone(s)", response.items.len()),
        data: to_response_data(response)?,
    })
}

/// Handle the `CreateZone` command by creating a new zone.
pub(crate) async fn create_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let request: CreateZoneRequest = parse_params(data)?;

    let zone = ZoneService::create(&Caller::Global, &request).await?;
    Ok(DaemonResponse {
        message: "Zone created successfully".to_string(),
        data: to_response_data(GetZoneResponse::from_zone(&zone))?,
    })
}

/// Handle the `UpdateZone` command by applying a partial-update patch.
pub(crate) async fn update_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateZoneParams = parse_params(data)?;

    let zone = ZoneService::patch(&Caller::Global, &params.name, &params.patch).await?;
    Ok(DaemonResponse {
        message: "Zone updated successfully".to_string(),
        data: to_response_data(GetZoneResponse::from_zone(&zone))?,
    })
}

/// Handle the `ImportZoneFile` command by reconciling BIND zone file text with
/// a zone in a single transaction.
pub(crate) async fn import_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ImportZoneFileParams = parse_params(data)?;

    let response =
        RecordService::import_zone_file(&Caller::Global, &params.zone_name, &params.request)
            .await?;
    import_zone_response(response)
}

/// Handle the `ImportZoneFromServer` command by transferring the zone over
/// AXFR and reconciling it like a file import.
pub(crate) async fn import_zone_from_server(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ImportZoneFromServerParams = parse_params(data)?;

    let response =
        RecordService::import_zone_from_server(&Caller::Global, &params.zone_name, &params.request)
            .await?;
    import_zone_response(response)
}

fn import_zone_response(response: ImportZoneFileResponse) -> Result<DaemonResponse, ServiceError> {
    let message = if !response.errors.is_empty() {
        format!(
            "Import validation failed with {} error(s); nothing applied",
            response.errors.len()
        )
    } else if response.dry_run {
        "Dry run completed; no changes applied".to_string()
    } else {
        "Zone file imported successfully".to_string()
    };

    Ok(DaemonResponse {
        message,
        data: to_response_data(response)?,
    })
}

/// Handle the `ExportZoneFile` command by rendering a zone as master-file text.
pub(crate) async fn export_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ExportZoneFileParams = parse_params(data)?;
    let zone_file =
        ZoneService::export_zone_file(&Caller::Global, &params.name, params.signed).await?;
    Ok(DaemonResponse {
        message: "Zone exported successfully".to_string(),
        data: to_response_data(ExportZoneFileResponse { zone_file })?,
    })
}

/// Handle the `ListZoneVersions` command by returning a zone's serial history.
pub(crate) async fn list_zone_versions(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ListZoneVersionsParams = parse_params(data)?;

    let response = ZoneService::list_versions(
        &Caller::Global,
        &params.name,
        params.limit,
        params.offset,
        params.all,
    )
    .await?;

    Ok(DaemonResponse {
        message: format!("Found {} version(s)", response.items.len()),
        data: to_response_data(response)?,
    })
}

/// Handle the `GetZoneVersion` command by returning one version with its
/// reconstructed record set.
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

/// Handle the `DiffZoneVersions` command by diffing two of a zone's serials.
/// A missing `to_serial` compares `from_serial` against the current serial.
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

/// Handle the `RollbackZone` command by rolling a zone back to a version serial.
pub(crate) async fn rollback_zone(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: RollbackZoneParams = parse_params(data)?;

    let response = ZoneService::rollback(
        &Caller::Global,
        &params.name,
        params.request.serial,
        params.request.dry_run,
    )
    .await?;
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

/// Handle the `ZoneStatus` command by probing every configured secondary for
/// the SOA serial it serves and comparing it with the zone's serial.
pub(crate) async fn zone_status(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
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

/// Handle the `DeleteZone` command by deleting a zone by name.
pub(crate) async fn delete_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    ZoneService::delete(&Caller::Global, &params.name).await?;
    Ok(DaemonResponse {
        message: format!("Zone '{}' deleted successfully", params.name),
        data: json!(null),
    })
}
