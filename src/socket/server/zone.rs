use crate::api::dto::{CreateZoneRequest, GetZoneResponse};
use crate::api::service::zone::ZoneService;
use crate::socket::dto::DaemonResponse;
use serde_json::json;

pub async fn get_zone(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let id = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")? as i32;

    match ZoneService::get_zone(id).await {
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

pub async fn list_zones() -> Result<DaemonResponse, String> {
    match ZoneService::get_zones().await {
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

pub async fn create_zone(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let request: CreateZoneRequest =
        serde_json::from_value(data.clone()).map_err(|e| format!("Invalid request data: {}", e))?;

    match ZoneService::create_zone(&request).await {
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

pub async fn delete_zone(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let id = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")? as i32;

    match ZoneService::delete_zone(id).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Zone {} deleted successfully", id),
            data: json!(null),
        }),
        Err(e) => Err(e.to_string()),
    }
}
