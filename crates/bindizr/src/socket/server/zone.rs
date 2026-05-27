use crate::api::dto::{CreateZoneRequest, GetZoneResponse};
use crate::service::zone::ZoneService;
use crate::socket::dto::DaemonResponse;
use serde_json::json;

pub(super) async fn get_zone(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'name' field")?;

    match ZoneService::get_by_name(name).await {
        Ok(zone) => {
            let response = GetZoneResponse::from_zone(&zone);
            Ok(DaemonResponse {
                message: "Zone retrieved successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn list_zones() -> Result<DaemonResponse, String> {
    match ZoneService::list().await {
        Ok(zones) => {
            let response: Vec<GetZoneResponse> =
                zones.iter().map(GetZoneResponse::from_zone).collect();
            Ok(DaemonResponse {
                message: format!("Found {} zone(s)", response.len()),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn create_zone(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let request: CreateZoneRequest =
        serde_json::from_value(data.clone()).map_err(|e| format!("Invalid request data: {}", e))?;

    match ZoneService::create(&request).await {
        Ok(zone) => {
            let response = GetZoneResponse::from_zone(&zone);
            Ok(DaemonResponse {
                message: "Zone created successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn delete_zone(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'name' field")?;

    match ZoneService::delete(name).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Zone '{}' deleted successfully", name),
            data: json!(null),
        }),
        Err(e) => Err(e.to_string()),
    }
}
