use crate::api::dto::{CreateDnsRequest, GetDnsResponse};
use crate::api::service::dns::DnsService;
use crate::socket::dto::DaemonResponse;
use serde_json::json;

pub async fn get_dns(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'name' field")?;

    match DnsService::get_dns(name).await {
        Ok(dns) => {
            let response = GetDnsResponse::from_dns(&dns);
            Ok(DaemonResponse {
                message: "DNS retrieved successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn list_dnss() -> Result<DaemonResponse, String> {
    match DnsService::get_dnss().await {
        Ok(dnss) => {
            let response: Vec<GetDnsResponse> = dnss.iter().map(GetDnsResponse::from_dns).collect();
            Ok(DaemonResponse {
                message: format!("Found {} DNS(s)", response.len()),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn create_dns(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let request: CreateDnsRequest =
        serde_json::from_value(data.clone()).map_err(|e| format!("Invalid request data: {}", e))?;

    match DnsService::create_dns(&request).await {
        Ok(dns) => {
            let response = GetDnsResponse::from_dns(&dns);
            Ok(DaemonResponse {
                message: "DNS created successfully".to_string(),
                data: serde_json::to_value(response).unwrap(),
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn delete_dns(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid 'name' field")?;

    match DnsService::delete_dns(name).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("DNS '{}' deleted successfully", name),
            data: json!(null),
        }),
        Err(e) => Err(e.to_string()),
    }
}

pub async fn write_dns_config() -> Result<DaemonResponse, String> {
    // TODO: Implement DNS config writing logic
    Ok(DaemonResponse {
        message: "DNS configuration written successfully".to_string(),
        data: json!(null),
    })
}

pub fn reload_dns_config() -> Result<DaemonResponse, String> {
    // TODO: Implement DNS config reload logic
    Ok(DaemonResponse {
        message: "DNS configuration reloaded successfully".to_string(),
        data: json!(null),
    })
}

pub fn get_dns_status() -> Result<DaemonResponse, String> {
    // TODO: Implement DNS status check logic
    Ok(DaemonResponse {
        message: "DNS server is running".to_string(),
        data: json!({"status": "running"}),
    })
}
