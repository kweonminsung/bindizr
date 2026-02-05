use crate::api::dto::{CreateDnsInstanceRequest, GetDnsInstanceResponse};
use crate::api::service::dns_instance::DnsInstanceService;
use crate::socket::dto::DaemonResponse;
use serde_json::json;

pub async fn get_dns_instance(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let id = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")?
        as i32;

    match DnsInstanceService::get_dns_instance(id).await {
        Ok(dns_instance) => {
            let response = GetDnsInstanceResponse::from_dns_instance(&dns_instance);
            Ok(DaemonResponse {
                message: "DNS instance retrieved successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn list_dns_instances() -> Result<DaemonResponse, String> {
    match DnsInstanceService::get_dns_instances().await {
        Ok(dns_instances) => {
            let response: Vec<GetDnsInstanceResponse> = dns_instances
                .iter()
                .map(GetDnsInstanceResponse::from_dns_instance)
                .collect();
            Ok(DaemonResponse {
                message: format!("Found {} DNS instance(s)", response.len()),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn create_dns_instance(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let request: CreateDnsInstanceRequest =
        serde_json::from_value(data.clone()).map_err(|e| format!("Invalid request data: {}", e))?;

    match DnsInstanceService::create_dns_instance(&request).await {
        Ok(dns_instance) => {
            let response = GetDnsInstanceResponse::from_dns_instance(&dns_instance);
            Ok(DaemonResponse {
                message: "DNS instance created successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn delete_dns_instance(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let id = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")?
        as i32;

    match DnsInstanceService::delete_dns_instance(id).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("DNS instance {} deleted successfully", id),
            data: json!(null),
        }),
        Err(e) => Err(e.to_string()),
    }
}
