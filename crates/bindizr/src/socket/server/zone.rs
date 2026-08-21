use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    record::RecordService,
    types::{
        CreateZoneRequest, ExportZoneFileResponse, GetZoneResponse, GetZonesFilter,
        VersionDetailResponse, VersionRecordResponse, ZoneVersionResponse,
    },
    zone::ZoneService,
};
use serde_json::json;

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{
        DaemonResponse, DiffZoneVersionsParams, ImportZoneFileParams, ListZoneVersionsParams,
        RollbackZoneParams, UpdateZoneParams, ZoneNameParams, ZoneVersionParams,
    },
};

/// Handle the `GetZone` command by returning a zone by name.
pub(super) async fn get_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let zone = ZoneService::get_by_name(&Caller::Global, &params.name).await?;
    Ok(DaemonResponse {
        message: "Zone retrieved successfully".to_string(),
        data: to_response_data(GetZoneResponse::from_zone(&zone))?,
    })
}

/// Handle the `ListZones` command by returning zones matching the filter.
pub(super) async fn list_zones(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let filter: GetZonesFilter = if data.is_null() {
        GetZonesFilter::default()
    } else {
        parse_params(data)?
    };

    let zones = ZoneService::list_by_filter(&Caller::Global, filter).await?;
    let response: Vec<GetZoneResponse> =
        zones.items.iter().map(GetZoneResponse::from_zone).collect();
    Ok(DaemonResponse {
        message: format!("Found {} zone(s)", response.len()),
        data: json!({
            "items": response,
            "pagination": zones.pagination,
        }),
    })
}

/// Handle the `CreateZone` command by creating a new zone.
pub(super) async fn create_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let request: CreateZoneRequest = parse_params(data)?;

    let zone = ZoneService::create(&Caller::Global, &request).await?;
    Ok(DaemonResponse {
        message: "Zone created successfully".to_string(),
        data: to_response_data(GetZoneResponse::from_zone(&zone))?,
    })
}

/// Handle the `UpdateZone` command by applying a partial-update patch.
pub(super) async fn update_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateZoneParams = parse_params(data)?;

    let zone = ZoneService::patch(&Caller::Global, &params.name, &params.patch).await?;
    Ok(DaemonResponse {
        message: "Zone updated successfully".to_string(),
        data: to_response_data(GetZoneResponse::from_zone(&zone))?,
    })
}

/// Handle the `ImportZoneFile` command by reconciling BIND zone file text with
/// a zone in a single transaction.
pub(super) async fn import_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ImportZoneFileParams = parse_params(data)?;

    let response =
        RecordService::import_zone_file(&Caller::Global, &params.zone_name, &params.request)
            .await?;
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
pub(super) async fn export_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;
    let zone_file = ZoneService::export_zone_file(&Caller::Global, &params.name).await?;
    Ok(DaemonResponse {
        message: "Zone exported successfully".to_string(),
        data: to_response_data(ExportZoneFileResponse { zone_file })?,
    })
}

/// Handle the `ListZoneVersions` command by returning a zone's serial history.
pub(super) async fn list_zone_versions(
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
    let items = response
        .items
        .iter()
        .map(ZoneVersionResponse::from_version)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DaemonResponse {
        message: format!("Found {} version(s)", items.len()),
        data: json!({
            "items": items,
            "pagination": response.pagination,
        }),
    })
}

/// Handle the `GetZoneVersion` command by returning one version with its
/// reconstructed record set.
pub(super) async fn get_zone_version(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneVersionParams = parse_params(data)?;

    let (version, records) =
        ZoneService::get_version(&Caller::Global, &params.name, params.serial).await?;
    let response = VersionDetailResponse {
        version: ZoneVersionResponse::from_version(&version)?,
        records: records
            .into_iter()
            .map(VersionRecordResponse::from)
            .collect(),
    };

    Ok(DaemonResponse {
        message: format!("Version '{}' retrieved successfully", params.serial),
        data: to_response_data(response)?,
    })
}

/// Handle the `DiffZoneVersions` command by diffing two of a zone's serials.
/// A missing `to_serial` compares `from_serial` against the current serial.
pub(super) async fn diff_zone_versions(
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
pub(super) async fn rollback_zone(
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
pub(super) async fn zone_status(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    let response = bindizr_dns::status::zone_status(&Caller::Global, &params.name).await?;

    let in_sync = response
        .secondaries
        .iter()
        .filter(|s| s.status == "in_sync")
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
pub(super) async fn delete_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: ZoneNameParams = parse_params(data)?;

    ZoneService::delete(&Caller::Global, &params.name).await?;
    Ok(DaemonResponse {
        message: format!("Zone '{}' deleted successfully", params.name),
        data: json!(null),
    })
}
