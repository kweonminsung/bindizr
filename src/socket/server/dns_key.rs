use crate::api::dto::{CreateDnsKeyRequest, GetDnsKeyResponse};
use crate::api::service::dns_key::DnsKeyService;
use crate::socket::dto::DaemonResponse;
use serde_json::json;

pub async fn get_dns_key(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let id = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")? as i32;

    match DnsKeyService::get_dns_key(id).await {
        Ok(dns_key) => {
            let response = GetDnsKeyResponse::from_dns_key(&dns_key);
            Ok(DaemonResponse {
                message: "DNS key retrieved successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn list_dns_keys() -> Result<DaemonResponse, String> {
    match DnsKeyService::get_dns_keys().await {
        Ok(dns_keys) => {
            let response: Vec<GetDnsKeyResponse> = dns_keys
                .iter()
                .map(GetDnsKeyResponse::from_dns_key)
                .collect();
            Ok(DaemonResponse {
                message: format!("Found {} DNS key(s)", response.len()),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn create_dns_key(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let request: CreateDnsKeyRequest =
        serde_json::from_value(data.clone()).map_err(|e| format!("Invalid request data: {}", e))?;

    match DnsKeyService::create_dns_key(&request).await {
        Ok(dns_key) => {
            let response = GetDnsKeyResponse::from_dns_key(&dns_key);
            Ok(DaemonResponse {
                message: "DNS key created successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn delete_dns_key(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let id = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or("Missing or invalid 'id' field")? as i32;

    match DnsKeyService::delete_dns_key(id).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("DNS key {} deleted successfully", id),
            data: json!(null),
        }),
        Err(e) => Err(e.to_string()),
    }
}
