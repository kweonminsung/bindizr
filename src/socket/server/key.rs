use crate::api::service::key::KeyService;
use crate::socket::dto::DaemonResponse;
use crate::{log_debug, log_error};
use serde_json::{Value, json};

pub async fn get_key(data: &Value) -> Result<DaemonResponse, String> {
    let name = data["name"].as_str().unwrap_or("default").to_string();

    log_debug!("Getting key: {}", name);

    match KeyService::get_key(&name).await {
        Ok(key) => Ok(DaemonResponse {
            message: format!("Key '{}' retrieved successfully", name),
            data: json!(key),
        }),
        Err(e) => Err(format!("Failed to get key: {}", e)),
    }
}

pub async fn list_keys() -> Result<DaemonResponse, String> {
    log_debug!("Listing all keys");

    match KeyService::get_keys().await {
        Ok(keys) => Ok(DaemonResponse {
            message: format!("{} keys retrieved successfully", keys.len()),
            data: json!(keys),
        }),
        Err(e) => {
            log_error!("Failed to list keys: {}", e);
            Err(format!("Failed to list keys: {}", e))
        }
    }
}

pub async fn create_key(data: &Value) -> Result<DaemonResponse, String> {
    let name = data["name"].as_str().unwrap_or("default").to_string();

    log_debug!("Creating key: {}", name);

    let request = match serde_json::from_value(data.clone()) {
        Ok(req) => req,
        Err(e) => return Err(format!("Invalid request data: {}", e)),
    };

    match KeyService::create_key(&request).await {
        Ok(key) => Ok(DaemonResponse {
            message: format!("Key '{}' created successfully", name),
            data: json!(key),
        }),
        Err(e) => Err(format!("Failed to create key: {}", e)),
    }
}

pub async fn delete_key(data: &Value) -> Result<DaemonResponse, String> {
    let name = data["name"].as_str().unwrap_or("default").to_string();

    log_debug!("Deleting key: {}", name);

    match KeyService::delete_key(&name).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Key '{}' deleted successfully", name),
            data: json!({}),
        }),
        Err(e) => Err(format!("Failed to delete key: {}", e)),
    }
}
