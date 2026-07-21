use bindizr_service::{error::ServiceError, record::RecordService, zone::ZoneService};
use serde_json::json;

use crate::{
    api::types::{CreateZoneRequest, GetZoneResponse, GetZonesFilter, ImportZoneFileRequest},
    socket::types::DaemonResponse,
};

/// Handle the `GetZone` command by returning a zone by name.
pub(super) async fn get_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ServiceError::invalid_input("Missing or invalid 'name' field"))?;

    match ZoneService::get_by_name(name).await {
        Ok(zone) => {
            let response = GetZoneResponse::from_zone(&zone);
            Ok(DaemonResponse {
                message: "Zone retrieved successfully".to_string(),
                data: serde_json::to_value(response).map_err(|e| {
                    ServiceError::internal(format!("Failed to serialize response: {}", e))
                })?,
            })
        }
        Err(e) => Err(e),
    }
}

/// Handle the `ListZones` command by returning zones matching the filter.
pub(super) async fn list_zones(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let filter = if data.is_null() {
        GetZonesFilter::default()
    } else {
        serde_json::from_value(data.clone())
            .map_err(|e| ServiceError::invalid_input(format!("Invalid filter data: {}", e)))?
    };

    match ZoneService::list_by_filter(filter).await {
        Ok(zones) => {
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
        Err(e) => Err(e),
    }
}

/// Handle the `CreateZone` command by creating a new zone.
pub(super) async fn create_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let request: CreateZoneRequest = serde_json::from_value(data.clone())
        .map_err(|e| ServiceError::invalid_input(format!("Invalid request data: {}", e)))?;

    match ZoneService::create(&request).await {
        Ok(zone) => {
            let response = GetZoneResponse::from_zone(&zone);
            Ok(DaemonResponse {
                message: "Zone created successfully".to_string(),
                data: serde_json::to_value(response).map_err(|e| {
                    ServiceError::internal(format!("Failed to serialize response: {}", e))
                })?,
            })
        }
        Err(e) => Err(e),
    }
}

/// Handle the `ImportZoneFile` command by reconciling BIND zone file text with
/// a zone in a single transaction.
pub(super) async fn import_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let zone_name = data
        .get("zone_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ServiceError::invalid_input("Missing or invalid 'zone_name' field"))?;
    let request: ImportZoneFileRequest = serde_json::from_value(data.clone())
        .map_err(|e| ServiceError::invalid_input(format!("Invalid request data: {}", e)))?;

    match RecordService::import_zone_file(zone_name, &request).await {
        Ok(response) => {
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
                data: serde_json::to_value(response).map_err(|e| {
                    ServiceError::internal(format!("Failed to serialize response: {}", e))
                })?,
            })
        }
        Err(e) => Err(e),
    }
}

/// Handle the `DeleteZone` command by deleting a zone by name.
pub(super) async fn delete_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ServiceError::invalid_input("Missing or invalid 'name' field"))?;

    match ZoneService::delete(name).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Zone '{}' deleted successfully", name),
            data: json!(null),
        }),
        Err(e) => Err(e),
    }
}
