use crate::api::types::{CreateRecordRequest, GetRecordResponse};
use crate::service::{record::RecordService, zone::ZoneService};
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

    match RecordService::get_by_id(record_id).await {
        Ok(record) => {
            let response = ZoneService::find_by_id(record.zone_id)
                .await
                .ok()
                .flatten()
                .map(|zone| GetRecordResponse::from_record_with_zone(&record, &zone.name))
                .unwrap_or_else(|| GetRecordResponse::from_record(&record));
            Ok(DaemonResponse {
                message: "Record retrieved successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn list_records(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let zone_name = data
        .get("zone_name")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    let records = if let Some(zone_name) = zone_name {
        RecordService::list(Some(zone_name)).await
    } else {
        RecordService::list(None).await
    };

    match records {
        Ok(records) => {
            let mut response: Vec<GetRecordResponse> = Vec::new();

            for record in records.iter() {
                let rec_response = ZoneService::find_by_id(record.zone_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|zone| GetRecordResponse::from_record_with_zone(record, &zone.name))
                    .unwrap_or_else(|| GetRecordResponse::from_record(record));

                response.push(rec_response);
            }

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
            let response = ZoneService::find_by_id(record.zone_id)
                .await
                .ok()
                .flatten()
                .map(|zone| GetRecordResponse::from_record_with_zone(&record, &zone.name))
                .unwrap_or_else(|| GetRecordResponse::from_record(&record));

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
