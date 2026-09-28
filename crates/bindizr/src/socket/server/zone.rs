use bindizr_core::{dns::Serial, model::zone_version::VersionScope};
use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    record,
    types::{
        CreateZoneRequest, DeleteZoneResponse, ExportZoneFileResponse, GetZoneResponse,
        GetZonesFilter, ImportZoneRequest, ImportZoneResponse, PaginatedResponse,
        RollbackZoneResponse, Run, UpdateZoneRequest, VersionDetailResponse, VersionDiffResponse,
        ZoneResponse, ZoneStatusResponse, ZoneVersionResponse, ZoneView, ZoneWriteResponse,
    },
    zone,
};

use crate::socket::types::DaemonResponse;

/// Return the requested zone.
pub(crate) async fn get_zone(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<ZoneResponse>, ServiceError> {
    let zone = zone::get_by_name(cx, &Caller::Global, name).await?;
    Ok(DaemonResponse {
        message: "Zone retrieved successfully".to_string(),
        data: ZoneResponse {
            zone: GetZoneResponse::from(&zone),
        },
    })
}

/// Return zones matching the request filters.
pub(crate) async fn list_zones(
    cx: &Context,
    filter: GetZonesFilter,
) -> Result<DaemonResponse<PaginatedResponse<GetZoneResponse>>, ServiceError> {
    let response = zone::list_by_filter(cx, &Caller::Global, filter).await?;
    Ok(DaemonResponse {
        message: "Zones retrieved successfully".to_string(),
        data: response,
    })
}

/// Create a zone from the control request.
pub(crate) async fn create_zone(
    cx: &Context,
    request: &CreateZoneRequest,
) -> Result<DaemonResponse<ZoneWriteResponse>, ServiceError> {
    let response = zone::create(cx, &Caller::Global, request).await?;
    Ok(DaemonResponse {
        message: if response.dry_run {
            "Zone would be created".to_string()
        } else {
            "Zone created successfully".to_string()
        },
        data: response,
    })
}

/// Update the requested zone.
pub(crate) async fn update_zone(
    cx: &Context,
    zone_name: &str,
    request: &UpdateZoneRequest,
) -> Result<DaemonResponse<ZoneWriteResponse>, ServiceError> {
    let response = zone::update(cx, &Caller::Global, zone_name, request).await?;
    Ok(DaemonResponse {
        message: if response.dry_run {
            "Zone would be updated".to_string()
        } else {
            "Zone updated successfully".to_string()
        },
        data: response,
    })
}

/// Preview or apply records imported into the requested zone.
pub(crate) async fn import_zone(
    cx: &Context,
    zone_name: &str,
    request: &ImportZoneRequest,
) -> Result<DaemonResponse<ImportZoneResponse>, ServiceError> {
    let response = record::import_zone(cx, &Caller::Global, zone_name, request).await?;
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
        data: response,
    })
}

/// Export the requested zone as a zone file.
pub(crate) async fn export_zone(
    cx: &Context,
    name: &str,
    view: ZoneView,
) -> Result<DaemonResponse<ExportZoneFileResponse>, ServiceError> {
    let zone_file = zone::export(cx, &Caller::Global, name, view).await?;
    Ok(DaemonResponse {
        message: "Zone exported successfully".to_string(),
        data: ExportZoneFileResponse { zone_file },
    })
}

/// Return the requested zone's version history.
pub(crate) async fn list_zone_versions(
    cx: &Context,
    name: &str,
    limit: Option<u32>,
    offset: Option<u64>,
    scope: VersionScope,
) -> Result<DaemonResponse<PaginatedResponse<ZoneVersionResponse>>, ServiceError> {
    let response = zone::list_versions(cx, &Caller::Global, name, limit, offset, scope).await?;
    Ok(DaemonResponse {
        message: "Versions retrieved successfully".to_string(),
        data: response,
    })
}

/// Return a zone version with the records it held.
pub(crate) async fn get_zone_version(
    cx: &Context,
    name: &str,
    serial: Serial,
) -> Result<DaemonResponse<VersionDetailResponse>, ServiceError> {
    let response = zone::get_version(cx, &Caller::Global, name, serial).await?;
    Ok(DaemonResponse {
        message: format!("Version '{}' retrieved successfully", serial),
        data: response,
    })
}

/// Compare two zone versions, using the current serial when `to_serial` is omitted.
pub(crate) async fn diff_zone_versions(
    cx: &Context,
    name: &str,
    from_serial: Serial,
    to_serial: Option<Serial>,
) -> Result<DaemonResponse<VersionDiffResponse>, ServiceError> {
    let response = zone::diff_versions(cx, &Caller::Global, name, from_serial, to_serial).await?;
    Ok(DaemonResponse {
        message: format!(
            "Serial {} -> {}: +{} -{} ~{}",
            response.from_serial,
            response.to_serial,
            response.diff.summary.added,
            response.diff.summary.removed,
            response.diff.summary.changed
        ),
        data: response,
    })
}

/// Preview or apply a rollback to the requested zone version.
pub(crate) async fn rollback_zone(
    cx: &Context,
    name: &str,
    serial: Serial,
    run: Run,
) -> Result<DaemonResponse<RollbackZoneResponse>, ServiceError> {
    let response = zone::rollback(cx, &Caller::Global, name, serial, run).await?;
    let message = if response.dry_run {
        format!(
            "Dry run: rollback to serial {} would add {} and delete {} record(s); nothing applied",
            response.target_serial, response.summary.added, response.summary.deleted
        )
    } else {
        format!(
            "Zone rolled back to serial {} (new serial {})",
            response.target_serial, response.new_serial
        )
    };
    Ok(DaemonResponse {
        message,
        data: response,
    })
}

/// Return the requested zone's primary and secondary status.
pub(crate) async fn get_zone_status(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<ZoneStatusResponse>, ServiceError> {
    let response = zone::get_status(cx, &Caller::Global, name).await?;
    let in_sync = response
        .secondaries
        .iter()
        .filter(|s| s.is_in_sync())
        .count();
    let message = if response.secondaries.is_empty() {
        "No enabled secondaries".to_string()
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
        data: response,
    })
}

/// Delete the requested zone.
pub(crate) async fn delete_zone(
    cx: &Context,
    name: &str,
    run: Run,
) -> Result<DaemonResponse<DeleteZoneResponse>, ServiceError> {
    let response = zone::delete(cx, &Caller::Global, name, run).await?;
    Ok(DaemonResponse {
        message: if response.dry_run {
            format!(
                "Zone '{}' would be deleted with {} record(s) and {} version(s)",
                name, response.records_deleted, response.versions_deleted
            )
        } else {
            format!("Zone '{}' deleted successfully", name)
        },
        data: response,
    })
}
