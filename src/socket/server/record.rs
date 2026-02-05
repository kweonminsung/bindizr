use crate::api::dto::{CreateRecordRequest, GetRecordResponse};
use crate::api::service::record::RecordService;
use crate::socket::dto::DaemonResponse;
use serde_json::json;

pub async fn get_record(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let id = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")? as i32;

    match RecordService::get_record(id).await {
        Ok(record) => {
            let response = GetRecordResponse::from_record(&record);
            Ok(DaemonResponse {
                message: "Record retrieved successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn list_records(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let zone_id = data
        .get("zone_id")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);

    let records = if let Some(zone_id) = zone_id {
        RecordService::get_records(Some(zone_id)).await
    } else {
        RecordService::get_records(None).await
    };

    match records {
        Ok(records) => {
            let response: Vec<GetRecordResponse> =
                records.iter().map(GetRecordResponse::from_record).collect();
            Ok(DaemonResponse {
                message: format!("Found {} record(s)", response.len()),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn create_record(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let request: CreateRecordRequest =
        serde_json::from_value(data.clone()).map_err(|e| format!("Invalid request data: {}", e))?;

    match RecordService::create_record(&request).await {
        Ok(record) => {
            let response = GetRecordResponse::from_record(&record);
            Ok(DaemonResponse {
                message: "Record created successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn delete_record(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let id = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")? as i32;

    match RecordService::delete_record(id).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Record {} deleted successfully", id),
            data: json!(null),
        }),
        Err(e) => Err(e.to_string()),
    }
}
