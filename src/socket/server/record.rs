use crate::api::dto::{CreateRecordRequest, GetRecordResponse};
use crate::database::model::record::RecordType;
use crate::service::{record::RecordService, zone::ZoneService};
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
    let zone_name = data
        .get("zone_name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'zone_name' field")?;
    let record_type = RecordType::from_str(record_type)
        .map_err(|_| format!("Invalid record type: {}", record_type))?;
    let zone = ZoneService::get(zone_name)
        .await
        .map_err(|e| e.to_string())?;

    match RecordService::get(Some(zone.id), name, &record_type, None, None, false).await {
        Ok(record) => {
            let mut response = GetRecordResponse::from_record(&record);
            response.zone_name = Some(zone.name);
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
        RecordService::list(Some(zone_name)).await
    } else {
        RecordService::list(None).await
    };

    match records {
        Ok(records) => {
            let mut response: Vec<GetRecordResponse> = Vec::new();

            for record in records.iter() {
                let zone_name = ZoneService::find_by_id(record.zone_id)
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

    match RecordService::create(&request).await {
        Ok(record) => {
            let zone_name = ZoneService::find_by_id(record.zone_id)
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
    let zone_name = data
        .get("zone_name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'zone_name' field")?;

    match RecordService::delete(zone_name, name, record_type).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Record '{}' ({}) deleted successfully", name, record_type),
            data: json!(null),
        }),
        Err(e) => Err(e.to_string()),
    }
}
