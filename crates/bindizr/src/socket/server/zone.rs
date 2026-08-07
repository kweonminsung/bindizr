use bindizr_service::{error::ServiceError, record::RecordService, zone::ZoneService};
use serde_json::json;

use crate::{
    api::types::{
        CreateZoneRequest, GetZoneResponse, GetZonesFilter, ImportZoneFileRequest,
        SnapshotDetailResponse, SnapshotRecordResponse, UpdateZonePatch, ZoneSnapshotResponse,
        ZoneStatusResponse,
    },
    socket::{server::to_response_data, types::DaemonResponse},
};

fn required_name(data: &serde_json::Value) -> Result<&str, ServiceError> {
    data.get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ServiceError::invalid_input("Missing or invalid 'name' field"))
}

fn required_serial(data: &serde_json::Value) -> Result<i32, ServiceError> {
    let serial = data
        .get("serial")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ServiceError::invalid_input("Missing or invalid 'serial' field"))?;
    i32::try_from(serial).map_err(|_| ServiceError::invalid_input("Serial is out of range"))
}

/// Handle the `GetZone` command by returning a zone by name.
pub(super) async fn get_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let name = required_name(data)?;

    match ZoneService::get_by_name(name).await {
        Ok(zone) => {
            let response = GetZoneResponse::from_zone(&zone);
            Ok(DaemonResponse {
                message: "Zone retrieved successfully".to_string(),
                data: to_response_data(response)?,
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
                data: to_response_data(response)?,
            })
        }
        Err(e) => Err(e),
    }
}

/// Handle the `UpdateZone` command by applying a partial-update patch.
pub(super) async fn update_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let name = required_name(data)?;
    let patch: UpdateZonePatch = super::parse_params(data)?;

    let zone = ZoneService::patch(name, &patch).await?;
    Ok(DaemonResponse {
        message: "Zone updated successfully".to_string(),
        data: to_response_data(GetZoneResponse::from_zone(&zone))?,
    })
}

/// Handle the `ImportZoneFile` command by reconciling BIND zone file text with
/// a zone in a single transaction.
pub(super) async fn import_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let zone_name = super::required_zone_name(data)?;
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
                data: to_response_data(response)?,
            })
        }
        Err(e) => Err(e),
    }
}

/// Handle the `ExportZoneFile` command by rendering a zone as master-file text.
pub(super) async fn export_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let name = required_name(data)?;
    let zone_file = ZoneService::export_zone_file(name).await?;
    Ok(DaemonResponse {
        message: "Zone exported successfully".to_string(),
        data: json!({ "zone_file": zone_file }),
    })
}

/// Handle the `ListZoneSnapshots` command by returning a zone's serial history.
pub(super) async fn list_zone_snapshots(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let name = required_name(data)?;
    let limit = data
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|v| v.min(u64::from(u32::MAX)) as u32);
    let offset = data.get("offset").and_then(|v| v.as_u64());

    let response = ZoneService::list_snapshots(name, limit, offset).await?;
    let items = response
        .items
        .iter()
        .map(ZoneSnapshotResponse::from_snapshot)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DaemonResponse {
        message: format!("Found {} snapshot(s)", items.len()),
        data: json!({
            "items": items,
            "pagination": response.pagination,
        }),
    })
}

/// Handle the `GetZoneSnapshot` command by returning one snapshot with its
/// reconstructed record set.
pub(super) async fn get_zone_snapshot(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let name = required_name(data)?;
    let serial = required_serial(data)?;

    let (snapshot, records) = ZoneService::get_snapshot(name, serial).await?;
    let response = SnapshotDetailResponse {
        snapshot: ZoneSnapshotResponse::from_snapshot(&snapshot)?,
        records: records
            .into_iter()
            .map(SnapshotRecordResponse::from)
            .collect(),
    };

    Ok(DaemonResponse {
        message: format!("Snapshot '{}' retrieved successfully", serial),
        data: to_response_data(response)?,
    })
}

/// Handle the `DiffZoneSnapshots` command by diffing two of a zone's serials.
/// A missing `to_serial` compares `from_serial` against the current serial.
pub(super) async fn diff_zone_snapshots(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let name = required_name(data)?;
    let serial_field = |field: &str| -> Result<Option<i32>, ServiceError> {
        data.get(field)
            .and_then(|v| v.as_i64())
            .map(|v| {
                i32::try_from(v).map_err(|_| ServiceError::invalid_input("Serial is out of range"))
            })
            .transpose()
    };
    let from_serial = serial_field("from_serial")?
        .ok_or_else(|| ServiceError::invalid_input("Missing or invalid 'from_serial' field"))?;
    let to_serial = serial_field("to_serial")?;

    let response = ZoneService::diff_snapshots(name, from_serial, to_serial).await?;
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

/// Handle the `RollbackZone` command by rolling a zone back to a snapshot serial.
pub(super) async fn rollback_zone(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let name = required_name(data)?;
    let serial = required_serial(data)?;
    let dry_run = data
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let response = ZoneService::rollback(name, serial, dry_run).await?;
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
    let name = required_name(data)?;

    let zone = ZoneService::get_by_name(name).await?;
    let probes = bindizr_dns::client::probe::probe_secondaries(&zone.name)
        .await
        .map_err(|e| ServiceError::internal(e.to_string()))?;
    let response =
        ZoneStatusResponse::from_probes(&zone, probes.into_iter().map(|p| (p.address, p.result)));

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
    let name = required_name(data)?;

    match ZoneService::delete(name).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Zone '{}' deleted successfully", name),
            data: json!(null),
        }),
        Err(e) => Err(e),
    }
}
