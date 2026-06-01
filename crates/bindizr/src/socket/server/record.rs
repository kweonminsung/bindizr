use crate::api::types::{CreateRecordRequest, GetRecordResponse, GetRecordsFilter};
use crate::service::record::RecordService;
use crate::socket::types::DaemonResponse;
use serde_json::json;

pub(super) async fn get_record(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let record_id_i64 = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")?;
    let record_id =
        i32::try_from(record_id_i64).map_err(|_| "Record ID is out of range".to_string())?;
    if record_id < 0 {
        return Err("Record ID must be non-negative".to_string());
    }

    match RecordService::get_by_id_with_zone(record_id).await {
        Ok(record) => {
            let response = GetRecordResponse::from_record_with_zone(&record);
            Ok(DaemonResponse {
                message: "Record retrieved successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn list_records(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let filter = if data.is_null() {
        GetRecordsFilter::default()
    } else {
        serde_json::from_value(data.clone()).map_err(|e| format!("Invalid filter data: {}", e))?
    };

    match RecordService::list_with_zone_by_filter(filter).await {
        Ok(records) => {
            let response = records
                .iter()
                .map(GetRecordResponse::from_record_with_zone)
                .collect::<Vec<_>>();

            Ok(DaemonResponse {
                message: format!("Found {} record(s)", response.len()),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn create_record(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let request: CreateRecordRequest =
        serde_json::from_value(data.clone()).map_err(|e| format!("Invalid request data: {}", e))?;

    match RecordService::create(&request).await {
        Ok(record) => {
            let response = GetRecordResponse::from_record_with_zone(&record);

            Ok(DaemonResponse {
                message: "Record created successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn delete_record(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let record_id_i64 = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")?;
    let record_id =
        i32::try_from(record_id_i64).map_err(|_| "Record ID is out of range".to_string())?;
    if record_id < 0 {
        return Err("Record ID must be non-negative".to_string());
    }

    match RecordService::delete_by_id(record_id).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Record '{}' deleted successfully", record_id),
            data: json!(null),
        }),
        Err(e) => Err(e.to_string()),
    }
}
