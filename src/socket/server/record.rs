use crate::api::dto::{CreateRecordRequest, GetRecordResponse};
use crate::api::service::record::RecordService;
use crate::database::get_zone_repository;
use crate::socket::dto::DaemonResponse;
use serde_json::json;

pub async fn get_record(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'name' field")?;
    let record_type = data
        .get("record_type")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'record_type' field")?;

    match RecordService::get_record(name, record_type).await {
        Ok(record) => {
            let zone_repository = get_zone_repository();
            let zone_name = zone_repository
                .get_by_id(record.zone_id)
                .await
                .ok()
                .flatten()
                .map(|z| z.name)
                .unwrap_or_default();

            let mut response = GetRecordResponse::from_record(&record);
            response.zone_name = Some(zone_name);
            Ok(DaemonResponse {
                message: "Record retrieved successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn list_records(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let zone_name = data
        .get("zone_name")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    let records = if let Some(zone_name) = zone_name {
        RecordService::get_records(Some(zone_name)).await
    } else {
        RecordService::get_records(None).await
    };

    match records {
        Ok(records) => {
            let zone_repository = get_zone_repository();
            let mut response: Vec<GetRecordResponse> = Vec::new();

            for record in records.iter() {
                let zone_name = zone_repository
                    .get_by_id(record.zone_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|z| z.name)
                    .unwrap_or_default();

                let mut rec_response = GetRecordResponse::from_record(record);
                rec_response.zone_name = Some(zone_name);
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

pub async fn create_record(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let request: CreateRecordRequest =
        serde_json::from_value(data.clone()).map_err(|e| format!("Invalid request data: {}", e))?;

    match RecordService::create_record(&request).await {
        Ok(record) => {
            let zone_repository = get_zone_repository();
            let zone_name = zone_repository
                .get_by_id(record.zone_id)
                .await
                .ok()
                .flatten()
                .map(|z| z.name)
                .unwrap_or_default();

            let mut response = GetRecordResponse::from_record(&record);
            response.zone_name = Some(zone_name);
            Ok(DaemonResponse {
                message: "Record created successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn delete_record(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'name' field")?;
    let record_type = data
        .get("record_type")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'record_type' field")?;

    match RecordService::delete_record(name, record_type).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Record '{}' ({}) deleted successfully", name, record_type),
            data: json!(null),
        }),
        Err(e) => Err(e.to_string()),
    }
}
